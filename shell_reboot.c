
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/appmgr.h>
#include <psp2/sharedfb.h>
#include <taihen.h>


typedef struct _SharedFb_c {
	int pid;
	int memid;
	int unk_0x08;
	int enable;
} SharedFb_c;

typedef struct _SharedFb_b {
	int index;
	int mirror_blockid;
	int unk_0x08;
	int unk_0x0C;
	int begin_evf;
	int end_evf;
	SceSharedFbInfo fb_info;
	SharedFb_c list[16];
	int unk_0x170;
	int unk_0x174;
	int unk_0x178;
	int unk_0x17C;
	int unk_0x180;
	int unk_0x184;
	int unk_0x188;
	int unk_0x18C;
	int unk_0x190;
	int unk_0x194;
	int unk_0x198;
	int unk_0x19C;
	int unk_0x1A0;
	int unk_0x1A4;
	int unk_0x1A8;
	int unk_0x1AC;
} SharedFb_b;

typedef struct _SharedFb_a {
	SharedFb_b unk_0x00[2];
	int unk_0x360;
	SharedFb_b *unk_0x364;
	SceKernelFastMutex fastmutex;
	int shellRenderPort;
} SharedFb_a;

int module_get_offset(SceUID pid, SceUID moduleId, SceUInt32 segment, SceUInt32 offset, uintptr_t *dst);
int module_get_export_func(SceUID pid, const char *modname, SceNID lib_nid, SceNID func_nid, uintptr_t *func);

int (* sceKernelGrowPhyMemPart)(SceKernelPhyMemPart *pPhyMemPart, SceSize psize);
SceKernelPhyMemPart *(* sceKernelGetPhyMemPart)(SceUInt32 type);
int (* SceAppMgrForDriver_324DD34E)(const char *name, int type, const char *path, SceSize argSize, const void *pArgBlock, const void *pOpt);


int shell_reboot(void (* callback)(void)){

	VITASDK_BUILD_ASSERT(sizeof(SharedFb_a) == 0x3AC);

	SceUID moduleId;

	{ // SceAppMgr patch
		moduleId = ksceKernelSearchModuleByName("SceAppMgr");

		// Disabled Standby by Shell terminate.
		// offset 0x12ea for 3.200.010
		taiInjectDataForKernel(SCE_KERNEL_PROCESS_ID, moduleId, 0, 0x12ea, (const SceUInt8[4]){0x00, 0xBF, 0x00, 0x20}, 4);
	}

	SceUID shell_pid = ksceKernelSysrootGetShellPid();
	ksceKernelPrintf("shell_pid: 0x%X\n", shell_pid);
	ksceAppMgrKillProcess(shell_pid);

	do {
		ksceKernelDelayThread(200 * 1000);
		shell_pid = ksceKernelSysrootGetShellPid();
	} while(shell_pid >= 0);

	ksceKernelPrintf("Shell process killed.\n");

	callback();

	{ // SceAppMgr patch
		moduleId = ksceKernelSearchModuleByName("SceAppMgr");

		SharedFb_a *pSharedFb_a;

		// offset (0x810a7e8c - 0x81073000) for 3.200.010
		module_get_offset(SCE_KERNEL_PROCESS_ID, moduleId, 1, 0x810a7e8c - 0x81073000, (uintptr_t *)&pSharedFb_a);

		ksceKernelLockFastMutex(&(pSharedFb_a->fastmutex));

		for(int i=0;i<2;i++){
			for(int k=0;k<0x10;k++){
				if(pSharedFb_a->unk_0x00[i].list[k].memid >= 0){
					ksceKernelFreeMemBlock(pSharedFb_a->unk_0x00[i].list[k].memid);
				}
			}

			ksceKernelFreeMemBlock(pSharedFb_a->unk_0x00[i].mirror_blockid);
			ksceKernelDeleteEventFlag(pSharedFb_a->unk_0x00[i].begin_evf);
			ksceKernelDeleteEventFlag(pSharedFb_a->unk_0x00[i].end_evf);
			memset(&(pSharedFb_a->unk_0x00[i]), 0, sizeof(SharedFb_b));
			pSharedFb_a->unk_0x00[i].index = -1;
		}

		pSharedFb_a->unk_0x360 = 0;
		pSharedFb_a->unk_0x364 = NULL;
		pSharedFb_a->shellRenderPort = 0;
		ksceKernelUnlockFastMutex(&(pSharedFb_a->fastmutex));
	}

	{ // SceNetPs NetEvent fixing.
		int (* bnet_mutex_lock_priority)(void *mutex, void *a2);
		int (* bnet_mutex_unlock_priority)(void *mutex);
		void *SceNetKernelJumbo;
		SceNetKernelEvent *pEvent; // global
		void **ppNetEventList;

		moduleId = ksceKernelSearchModuleByName("SceNetPs");

		// all offset for 3.200.010
		module_get_offset(SCE_KERNEL_PROCESS_ID, moduleId, 0, 0x2953c | 1, (uintptr_t *)&bnet_mutex_lock_priority);
		module_get_offset(SCE_KERNEL_PROCESS_ID, moduleId, 0, 0x295b8 | 1, (uintptr_t *)&bnet_mutex_unlock_priority);
		module_get_offset(SCE_KERNEL_PROCESS_ID, moduleId, 1, 0x8102d850 - 0x8102d000, (uintptr_t *)&SceNetKernelJumbo);
		module_get_offset(SCE_KERNEL_PROCESS_ID, moduleId, 1, (0x810322e8 - 0x8102d000) + 0x30 + 0x38, (uintptr_t *)&pEvent);
		module_get_offset(SCE_KERNEL_PROCESS_ID, moduleId, 1, 0x81032194 - 0x8102d000, (uintptr_t *)&ppNetEventList);

		bnet_mutex_lock_priority(SceNetKernelJumbo, NULL);
		for(int i=0;i<3;i++){
			ksceKernelPrintf("[%-31s]: uNotifyId=0x%08X kNotifyId=0x%X\n", pEvent[i].name, pEvent[i].uNotifyId, pEvent[i].kNotifyId);
			pEvent[i].uNotifyId = 0;
			pEvent[i].flags &= ~1;
		}

		void *pNetEventList = *ppNetEventList;
		while(pNetEventList != NULL){
			uintptr_t ptr = *(uintptr_t *)((uintptr_t)pNetEventList + 0x34);
			if(ptr != 0){
				pEvent = (SceNetKernelEvent *)(ptr + 0x30 + 0x38);
				for(int i=0;i<3;i++){
					ksceKernelPrintf("[%-31s]: uNotifyId=0x%08X kNotifyId=0x%X\n", pEvent[i].name, pEvent[i].uNotifyId, pEvent[i].kNotifyId);
					pEvent[i].uNotifyId = 0;
					pEvent[i].flags &= ~1;
				}
			}


			pNetEventList = *(void **)(pNetEventList);
		}

		bnet_mutex_unlock_priority(SceNetKernelJumbo);
	}

	module_get_export_func(SCE_KERNEL_PROCESS_ID, "SceSysmem", 0x63A519E5, 0x6B3F4102, (uintptr_t *)&sceKernelGrowPhyMemPart);
	module_get_export_func(SCE_KERNEL_PROCESS_ID, "SceAppMgr", 0xDCE180F8, 0x324DD34E, (uintptr_t *)&SceAppMgrForDriver_324DD34E);
	module_get_export_func(SCE_KERNEL_PROCESS_ID, "SceProcessmgr", 0x7A69DE86, 0xCCB4289B, (uintptr_t *)&sceKernelGetPhyMemPart);

	if(0){
		SceKernelPhyMemPart *pShellPhyMemPart = sceKernelGetPhyMemPart(7);
		sceKernelGrowPhyMemPart(pShellPhyMemPart, 0x800000); // for noShared
	}

	if(1){
		/*
		 * param size is 0x40 bytes on 3.50 >=
		 */
		SceUInt32 param[15];
		memset(param, 0, sizeof(param));
		param[0] = sizeof(param);                      
		param[1] = 0x4000;
		param[6] = 3;

		int res = SceAppMgrForDriver_324DD34E("main", 0x04000000, "vs0:vsh/shell/shell.self", 0, NULL, param);

		ksceKernelPrintf("SceAppMgrForDriver_324DD34E 0x%X\n", res);
	}

	return 0;
}
