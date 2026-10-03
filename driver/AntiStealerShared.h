#pragma once

#define AS_PROTOCOL_VERSION 1
#define AS_PORT_NAME L"\\AntiStealerPort"
#define AS_MAX_PATH_CHARS 520
#define AS_MAX_POLICY_RULES 32
#define AS_MAX_PARENT_CHARS 128
#define AS_MAX_LEAF_CHARS 64
#define AS_POLICY_REPLACE 1

typedef enum _AS_TARGET_CATEGORY {
    AsTargetUnknown = 0,
    AsTargetChrome = 1,
    AsTargetEdge = 2,
    AsTargetFirefox = 3,
    AsTargetTelegram = 4,
    AsTargetDiscord = 5,
    AsTargetSteam = 6,
    AsTargetWindowsCredentials = 7,
    AsTargetCryptoWallet = 8
} AS_TARGET_CATEGORY;

typedef struct _AS_ACCESS_REQUEST {
    ULONG Version;
    ULONG ProcessId;
    ULONG DesiredAccess;
    ULONG Category;
    WCHAR Path[AS_MAX_PATH_CHARS];
} AS_ACCESS_REQUEST, *PAS_ACCESS_REQUEST;

typedef struct _AS_ACCESS_REPLY {
    ULONG Version;
    ULONG Verdict; // 1 = allow, 0 = deny
} AS_ACCESS_REPLY, *PAS_ACCESS_REPLY;

typedef struct _AS_PATH_RULE {
    ULONG Category;
    WCHAR ParentFragment[AS_MAX_PARENT_CHARS];
    WCHAR LeafFragment[AS_MAX_LEAF_CHARS];
} AS_PATH_RULE, *PAS_PATH_RULE;

typedef struct _AS_POLICY_UPDATE {
    ULONG Version;
    ULONG Command;
    ULONG RuleCount;
    ULONG Reserved;
    AS_PATH_RULE Rules[AS_MAX_POLICY_RULES];
} AS_POLICY_UPDATE, *PAS_POLICY_UPDATE;

C_ASSERT(sizeof(AS_ACCESS_REQUEST) == 1056);
C_ASSERT(sizeof(AS_ACCESS_REPLY) == 8);
C_ASSERT(sizeof(AS_PATH_RULE) == 388);
C_ASSERT(sizeof(AS_POLICY_UPDATE) == 12432);
