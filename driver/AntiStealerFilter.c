#include <fltKernel.h>
#include <ntstrsafe.h>
#include "AntiStealerShared.h"

PFLT_FILTER gFilter = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
EX_PUSH_LOCK gPolicyLock;
AS_POLICY_UPDATE gPolicy = { 0 };

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS AsUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS AsConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie);
static VOID AsDisconnect(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS AsMessage(_In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);
static FLT_PREOP_CALLBACK_STATUS AsPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, AsPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gOperations,
    AsUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static BOOLEAN AsContainsInsensitive(_In_ PCUNICODE_STRING Value, _In_ PCWSTR Fragment)
{
    SIZE_T fragmentChars = 0;
    SIZE_T valueChars = Value->Length / sizeof(WCHAR);
    SIZE_T index;
    SIZE_T inner;

    if (!NT_SUCCESS(RtlStringCchLengthW(Fragment, AS_MAX_PATH_CHARS, &fragmentChars)) || fragmentChars == 0 || fragmentChars > valueChars)
        return FALSE;

    for (index = 0; index <= valueChars - fragmentChars; ++index) {
        for (inner = 0; inner < fragmentChars; ++inner) {
            if (RtlUpcaseUnicodeChar(Value->Buffer[index + inner]) != RtlUpcaseUnicodeChar(Fragment[inner]))
                break;
        }
        if (inner == fragmentChars)
            return TRUE;
    }
    return FALSE;
}

static ULONG AsClassifySensitivePath(_In_ PCUNICODE_STRING Path)
{
    ULONG category = AsTargetUnknown;
    ULONG index;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gPolicyLock);
    for (index = 0; index < gPolicy.RuleCount; ++index) {
        PAS_PATH_RULE rule = &gPolicy.Rules[index];
        if (AsContainsInsensitive(Path, rule->ParentFragment) &&
            (rule->LeafFragment[0] == UNICODE_NULL || AsContainsInsensitive(Path, rule->LeafFragment))) {
            category = rule->Category;
            break;
        }
    }
    ExReleasePushLockShared(&gPolicyLock);
    KeLeaveCriticalRegion();
    return category;
}

static FLT_PREOP_CALLBACK_STATUS AsPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ACCESS_MASK desiredAccess;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    AS_ACCESS_REQUEST request = { 0 };
    AS_ACCESS_REPLY reply = { AS_PROTOCOL_VERSION, 1 };
    ULONG replyLength = sizeof(reply);
    ULONG category;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    HANDLE processId;
    SIZE_T copyChars;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode || Data->Iopb->Parameters.Create.SecurityContext == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if ((desiredAccess & (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | GENERIC_READ)) == 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if ((Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) != 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    category = AsClassifySensitivePath(&nameInfo->Name);
    if (category == AsTargetUnknown) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    processId = PsGetCurrentProcessId();
    if ((ULONG_PTR)processId <= 4 || gClientPort == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // fail open when the service is unavailable
    }

    request.Version = AS_PROTOCOL_VERSION;
    request.ProcessId = HandleToULong(processId);
    request.DesiredAccess = desiredAccess;
    request.Category = category;
    copyChars = min((SIZE_T)(nameInfo->Name.Length / sizeof(WCHAR)), (SIZE_T)(AS_MAX_PATH_CHARS - 1));
    RtlCopyMemory(request.Path, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
    request.Path[copyChars] = UNICODE_NULL;

    timeout.QuadPart = -15000000LL; // 1.5 s hard cap for first-time signature verification
    status = FltSendMessage(gFilter, &gClientPort, &request, sizeof(request),
        &reply, &replyLength, &timeout);
    FltReleaseFileNameInformation(nameInfo);

    if (NT_SUCCESS(status) && replyLength >= sizeof(reply) &&
        reply.Version == AS_PROTOCOL_VERSION && reply.Verdict == 0) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS AsConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (InterlockedCompareExchangePointer((PVOID volatile*)&gClientPort, ClientPort, NULL) != NULL)
        return STATUS_DEVICE_BUSY;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gPolicyLock);
    RtlZeroMemory(&gPolicy, sizeof(gPolicy));
    ExReleasePushLockExclusive(&gPolicyLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

static VOID AsDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gPolicyLock);
    RtlZeroMemory(&gPolicy, sizeof(gPolicy));
    ExReleasePushLockExclusive(&gPolicyLock);
    KeLeaveCriticalRegion();
    FltCloseClientPort(gFilter, &gClientPort);
}

static NTSTATUS AsMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    PAS_POLICY_UPDATE update;
    ULONG index;
    SIZE_T length;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (ReturnOutputBufferLength == NULL)
        return STATUS_INVALID_PARAMETER;
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength != sizeof(AS_POLICY_UPDATE))
        return STATUS_INFO_LENGTH_MISMATCH;

    update = (PAS_POLICY_UPDATE)InputBuffer;
    if (update->Version != AS_PROTOCOL_VERSION || update->Command != AS_POLICY_REPLACE ||
        update->RuleCount == 0 || update->RuleCount > AS_MAX_POLICY_RULES)
        return STATUS_INVALID_PARAMETER;

    for (index = 0; index < update->RuleCount; ++index) {
        if (update->Rules[index].Category == AsTargetUnknown ||
            !NT_SUCCESS(RtlStringCchLengthW(update->Rules[index].ParentFragment, AS_MAX_PARENT_CHARS, &length)) ||
            length == 0 ||
            !NT_SUCCESS(RtlStringCchLengthW(update->Rules[index].LeafFragment, AS_MAX_LEAF_CHARS, &length)))
            return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gPolicyLock);
    RtlCopyMemory(&gPolicy, update, sizeof(gPolicy));
    ExReleasePushLockExclusive(&gPolicyLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

static NTSTATUS AsUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gServerPort != NULL)
        FltCloseCommunicationPort(gServerPort);
    if (gClientPort != NULL)
        FltCloseClientPort(gFilter, &gClientPort);
    FltUnregisterFilter(gFilter);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializePushLock(&gPolicyLock);

    status = FltRegisterFilter(DriverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status))
        return status;

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        return status;
    }

    RtlInitUnicodeString(&portName, AS_PORT_NAME);
    InitializeObjectAttributes(&attributes, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDescriptor);
    status = FltCreateCommunicationPort(gFilter, &gServerPort, &attributes, NULL,
        AsConnect, AsDisconnect, AsMessage, 1);
    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        return status;
    }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilter);
    }
    return status;
}
