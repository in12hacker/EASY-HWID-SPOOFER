#pragma once
#include "util.hpp"
#include "log.hpp"
#include <ifdef.h>
#include <minwindef.h>
#include <ntddndis.h>
#include <Ntifs.h>
#include <ntddk.h>

namespace n_nic
{
	char permanent_mac[100]{ 0 };
	char current_mac[100]{ 0 };

	bool arp_table_handle = false;
	int mac_mode = 0;

#define  MAC_SIZE  6
	UCHAR g_mac[MAC_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };

	// dt ndis!_NDIS_IF_BLOCK
	/*
	dt ndis!_NDIS_IF_BLOCK
   +0x000 Header           : _NDIS_OBJECT_HEADER
   +0x008 Link             : _LIST_ENTRY
   +0x018 ProviderLink     : _LIST_ENTRY
   +0x028 NetworkLink      : _LIST_ENTRY
   +0x038 ifRcvAddressTable : Ptr64 _NDIS_IF_RCV_ADDRESS
   +0x040 ifRcvAddressCount : Uint4B
   +0x044 ifMaxRcvAddressCount : Uint4B
   +0x048 LowerLayerIfCount : Uint4B
   +0x04c HigherLayerIfCount : Uint4B
   +0x050 Ref              : Int4B
   +0x054 MiniportRef      : Int4B
   +0x058 NetLuid          : _NET_LUID_LH
   +0x060 ProviderIfContext : Ptr64 Void
   +0x068 ProviderHandle   : Ptr64 _NDIS_IF_PROVIDER_BLOCK
   +0x070 Flags            : Uint4B
   +0x074 PhysicalLocation : _NET_PHYSICAL_LOCATION_LH
   +0x080 WanTunnelType    : Uint4B
   +0x084 PortNumber       : Uint4B
   +0x088 ifLastChange     : Uint8B
   +0x090 ifCounterDiscontinuityTime : Uint8B
   +0x098 RosInfo          : UChar
   +0x098 ifIndex          : Uint4B
   +0x09c ifDescr          : _IF_COUNTED_STRING_LH
   +0x2a0 ifType           : Uint2B
   +0x2a4 AccessType       : _NET_IF_ACCESS_TYPE
   +0x2a8 DirectionType    : _NET_IF_DIRECTION_TYPE
   +0x2ac ConnectionType   : _NET_IF_CONNECTION_TYPE
   +0x2b0 InterfaceGuid    : _GUID
   +0x2c0 ifConnectorPresent : UChar
   +0x2c4 ifFlags          : Uint4B
   +0x2c8 MediaType        : _NDIS_MEDIUM
   +0x2cc PhysicalMediumType : _NDIS_PHYSICAL_MEDIUM
   +0x2d0 RodInfo          : UChar
   +0x2d0 CompartmentId    : Uint4B
   +0x2d4 NetworkGuid      : _GUID
   +0x2e4 ifAlias          : _IF_COUNTED_STRING_LH
   +0x4e8 ifOperStatus     : _NET_IF_OPER_STATUS
   +0x4ec ifOperStatusFlags : Uint4B
   +0x4f0 ifMtu            : Uint4B
   +0x4f4 ifPhysAddress    : _IF_PHYSICAL_ADDRESS_LH
   +0x516 PermanentPhysAddress : _IF_PHYSICAL_ADDRESS_LH
   +0x538 ifAdminStatus    : _NET_IF_ADMIN_STATUS
   +0x540 XmitLinkSpeed    : Uint8B
   +0x548 RcvLinkSpeed     : Uint8B
   +0x550 ifPromiscuousMode : UChar
   +0x551 ifDeviceWakeUpEnable : UChar
   +0x554 MediaConnectState : _NET_IF_MEDIA_CONNECT_STATE
   +0x558 MediaDuplexState : _NET_IF_MEDIA_DUPLEX_STATE
   +0x560 Network          : Ptr64 _NDIS_IF_NETWORK_BLOCK
   +0x568 Compartment      : Ptr64 _NDIS_IF_COMPARTMENT_BLOCK
   +0x570 AsyncEvent       : Ptr64 _KEVENT
   +0x578 MiniportAsyncEvent : Ptr64 _KEVENT
   +0x580 bNdisIsProvider  : UChar
   +0x581 MiniportPresent  : UChar
   +0x584 SupportedStatistics : Uint4B
   +0x588 ifL2NetworkInfo  : _IF_COUNTED_STRING_LH
	*/
#if (NTDDI_VERSION >= NTDDI_WIN10)
	typedef struct _NDIS_IF_BLOCK {
		char _padding_0[0x464];
		IF_PHYSICAL_ADDRESS_LH ifPhysAddress; // 0x464
		IF_PHYSICAL_ADDRESS_LH PermanentPhysAddress; // 0x486
	} NDIS_IF_BLOCK, *PNDIS_IF_BLOCK;
#else
	typedef struct _NDIS_IF_BLOCK {
		char _padding_0[0x4f4];
		IF_PHYSICAL_ADDRESS_LH ifPhysAddress; // 0x4f4
		IF_PHYSICAL_ADDRESS_LH PermanentPhysAddress; // 0x516
	} NDIS_IF_BLOCK, * PNDIS_IF_BLOCK;
#endif

	typedef struct _KSTRING {
		char _padding_0[0x10];
		WCHAR Buffer[1]; // 0x10 at least
	} KSTRING, *PKSTRING;

	typedef struct _NDIS_FILTER_DRIVER_BLOCK {
		char _padding_0[0x8];
		struct _NDIS_FILTER_DRIVER_BLOCK* NextFilterDriver;
		PDRIVER_OBJECT DriverObject;
		struct _NDIS_FILTER_BLOCK* FilterQueue;
	} NDIS_FILTER_DRIVER_BLOCK, * PNDIS_FILTER_DRIVER_BLOCK;

	//dt ndis!_NDIS_MINIPORT_BLOCK
	typedef struct _NDIS_MINIPORT_BLOCK {
		char _padding_0[0x1440];
		UNICODE_STRING BaseName;
		UNICODE_STRING MiniportName;
	} NDIS_MINIPORT_BLOCK, * PNDIS_MINIPORT_BLOCK;

	// dt ndis!_NDIS_FILTER_BLOCK
	typedef struct _NDIS_FILTER_BLOCK {
		char _padding_0[0x8];
		struct _NDIS_FILTER_BLOCK *NextFilter; // 0x8
		PNDIS_FILTER_DRIVER_BLOCK FilterDriver; //0x010
		char _padding_1[0x8];
		PNDIS_MINIPORT_BLOCK  Miniport;
		PKSTRING FilterInstanceName; // 0x28
	} NDIS_FILTER_BLOCK, *PNDIS_FILTER_BLOCK;

	typedef struct _NSI_PARAMS
	{
		__int64 field_0;
		__int64 field_8;
		__int64 field_10;
		int Type;
		int field_1C;
		int field_20;
		int field_24;
		char field_42;
		__int64 AddrTable;
		int AddrEntrySize;
		int field_34;
		__int64 NeighborTable;
		int NeighborTableEntrySize;
		int field_44;
		__int64 StateTable;
		int StateTableEntrySize;
		int field_54;
		__int64 OwnerTable;
		int OwnerTableEntrySize;
		int field_64;
		int Count;
		int field_6C;
	}NSI_PARAMS, *PNSI_PARAMS;

	typedef struct _NSI_PARAM_86
	{
		UINT UnknownParam0;    //0
		UINT UnknownParam1;    //0
		UINT UnknownParam2;    //NPI_MODULEID指针
		UINT UnknownParam3;    //硬编码
		UINT UnknownParam4;    //硬编码
		UINT UnknownParam5;    //硬编码
		UINT UnknownParam6;    //结构体1数组指针
		UINT UnknownParam7;    //结构体1大小
		UINT UnknownParam8;    //0
		UINT UnknownParam9;    //0
		UINT UnknownParam10;   //结构体2数组指针
		UINT UnknownParam11;   //结构体2大小
		UINT UnknownParam12;   //结构体3数组指针
		UINT UnknownParam13;   //结构体3数组指针
		UINT ConnCount;        //连接数
	}NSI_PARAM_86, * PNSI_PARAM_86;

	typedef struct _NSI_PARAM_64
	{
		ULONG_PTR  UnknownParam0;    //0
		ULONG_PTR  UnknownParam1;    //0
		ULONG_PTR  UnknownParam2;    //NPI_MODULEID指针
		ULONG_PTR  UnknownParam3;    //硬编码
		ULONG_PTR  UnknownParam4;    //硬编码
		ULONG_PTR  UnknownParam5;    //硬编码
		ULONG_PTR  UnknownParam6;    //结构体1数组指针
		ULONG_PTR  UnknownParam7;    //结构体1大小
		ULONG_PTR  UnknownParam8;    //0
		ULONG_PTR  UnknownParam9;    //0
		ULONG_PTR  UnknownParam10;   //结构体2数组指针
		ULONG_PTR  UnknownParam11;   //结构体2大小
		ULONG_PTR  UnknownParam12;   //结构体3数组指针
		ULONG_PTR  UnknownParam13;   //结构体3数组指针
		ULONG_PTR  ConnCount;        //连接数
	}NSI_PARAM_64, * PNSI_PARAM_64;

	typedef struct _NIC_ARRAY
	{
		PDRIVER_OBJECT driver_object;
		PDRIVER_DISPATCH original_function;
	}NIC_ARRAY, *PNIC_ARRAY;

	const int max_array_size = 20;
	int array_size = 0;
	NIC_ARRAY g_nic_array[max_array_size] = { 0 };
	KSPIN_LOCK g_lock;

	PDRIVER_DISPATCH g_original_arp_control = 0;

	wchar_t* paste_guid(wchar_t* str, size_t len)
	{
		if (str == 0) return 0;
		if (len == 0) len = wcslen(str);

		size_t index = 0;
		for (size_t i = 0; i < len; i++)
		{
			if (str[i] == L'{') index = i;
			else if (str[i] == L'}')
			{
				str[i + 1] = 0;
				break;
			}
		}

		return str + index;
	}

	typedef struct _LG_CONTEXT
	{
		PIO_COMPLETION_ROUTINE oldIocomplete;
		PVOID oldCtx;
		BOOLEAN bShouldInvolve;
		PKEVENT pEvent;
	}LG_CONTEXT, * PLG_CONTEXT;

	NTSTATUS
		LgCompletion(
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp,
			IN PVOID Context
		)
	{
		//PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
		PIO_STACK_LOCATION irpspNext = IoGetNextIrpStackLocation(Irp);
		PLG_CONTEXT pCtx = (PLG_CONTEXT)Context;

		if (NT_SUCCESS(Irp->IoStatus.Status))
		{

			if (pCtx->pEvent)
			{
				KeSetEvent(pCtx->pEvent, 0, 0);
			}
		}

		irpspNext->Context = pCtx->oldCtx;
		irpspNext->CompletionRoutine = pCtx->oldIocomplete;

		ExFreePool(Context);

		if (pCtx->bShouldInvolve)
		{
			return irpspNext->CompletionRoutine(DeviceObject, Irp, Context);
		}
		else
		{
			if (Irp->PendingReturned)
			{
				IoMarkIrpPending(Irp);
			}
			return STATUS_SUCCESS;
		}

	}

	NTSTATUS LgDeviceControlDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
	{
#define IOCTL_NSI_GETALLPARAM (0x0012001B)
#define IOCTL_ARP_TABLE (0x12000F)
#define NSI_PARAMS_ARP (11)
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PIO_STACK_LOCATION irpStack;
		ULONG      uIoControlCode;

		irpStack = IoGetCurrentIrpStackLocation(pIrp);
		uIoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
		//KdPrint(("uIoControlCode :%d\n", uIoControlCode));

		if (uIoControlCode == IOCTL_NSI_GETALLPARAM)
		{
			UNICODE_STRING uniNtPath = { 0 };
			WCHAR wszNtPath[MAX_PATH] = { 0 };

			RtlInitEmptyUnicodeString(&uniNtPath, wszNtPath, MAX_PATH);
			status = n_util::GetProcessImageName(PsGetCurrentProcessId(), &uniNtPath);
			if (NT_SUCCESS(status))
			{
				if (n_util::UniEndWithString(&uniNtPath, L"\\GETDEVICEINFO.EXE", TRUE))
				{
					KAPC_STATE ApcState;
					KEVENT Event;
					PEPROCESS pEprocess = IoGetCurrentProcess();
					PLG_CONTEXT pContext = (LG_CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(LG_CONTEXT), '1isn');

					KeInitializeEvent(&Event, NotificationEvent, 0);
					pContext->oldIocomplete = irpStack->CompletionRoutine;
					pContext->oldCtx = irpStack->Context;
					irpStack->CompletionRoutine = LgCompletion;
					irpStack->Context = pContext;
					pContext->pEvent = &Event;
					if ((irpStack->Control & SL_INVOKE_ON_SUCCESS) == SL_INVOKE_ON_SUCCESS)
					{
						pContext->bShouldInvolve = TRUE;
					}
					else
					{
						pContext->bShouldInvolve = FALSE;
					}
					irpStack->Control |= SL_INVOKE_ON_SUCCESS;

					status = g_original_arp_control(pDeviceObject, pIrp);
					KeWaitForSingleObject(&Event, Executive, 0, 0, 0);
					if (status == STATUS_SUCCESS)
					{
						PVOID pUserBuffer = pIrp->UserBuffer;
						if (MmIsAddressValid(pUserBuffer))
						{
							PVOID pBuffer2 = NULL;

							KeStackAttachProcess(pEprocess, &ApcState);

							{
								if (IoIs32bitProcess(0))
									pBuffer2 = (PVOID)(((PNSI_PARAM_86)pUserBuffer)->UnknownParam10);//(PVOID) * (ULONG*)((PUCHAR)pUserBuffer + 4 * 10);
								else
									pBuffer2 = (PVOID)(((PNSI_PARAM_64)pUserBuffer)->UnknownParam9);
								
								if (pBuffer2 != NULL)
								{
									PUCHAR pMac = NULL;
									//ULONG i = 0;

									PMDL pMdl = IoAllocateMdl((PUCHAR)pBuffer2 + 0x1186/* + 1968 * i*/, MAC_SIZE, FALSE, FALSE, NULL);

									__try
									{
										MmProbeAndLockPages(pMdl, UserMode, IoWriteAccess);
									}
									__except (EXCEPTION_EXECUTE_HANDLER)
									{
										IoFreeMdl(pMdl);
										goto label;
									}

									if (pMdl->MdlFlags & ((MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)))
									{
										pMac = (PUCHAR)pMdl->MappedSystemVa;
									}
									else
									{
										pMac = (PUCHAR)MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
									}


									//KdPrint(("pBuffer2:original mac == %02X-%02X-%02X-%02X-%02X-%02X\n", *pMac, *(pMac + 1), *(pMac + 2), *(pMac + 3), *(pMac + 4), *(pMac + 5)));

									RtlCopyMemory(pMac, g_mac, MAC_SIZE);

									//´Ë´¦£¬ÔÚwindbgÖÐ¿´µ½pIrp->userBufferÖÐµÄmacµØÖ·ÒÑ¾­±»¸ü¸Ä£¬µ«ÊÇÓ¦ÓÃ²ã³ÌÐò»¹ÊÇ·µ»ØÔ­À´µÄmac£¬Ð¡µÜÔõÃ´Ò²Ïë²»Ã÷°×£¿
									//KdPrint(("pBuffer2:modify mac == %02X-%02X-%02X-%02X-%02X-%02X\n", *pMac, *(pMac + 1), *(pMac + 2), *(pMac + 3), *(pMac + 4), *(pMac + 5)));

									MmUnlockPages(pMdl);
									IoFreeMdl(pMdl);
								}
							}
							KeUnstackDetachProcess(&ApcState);
						}
					}
					goto label;
				}
			}
		}

		status = g_original_arp_control(pDeviceObject, pIrp);
	label:
		return status;
	}

	NTSTATUS my_arp_handle_control(PDEVICE_OBJECT device, PIRP irp)
	{
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);

#define IOCTL_NSI_PROXY_ARP (0x0012001B)
#define IOCTL_ARP_TABLE (0x12000F)
#define NSI_PARAMS_ARP (11)

		switch (ioc->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_NSI_PROXY_ARP:
		case IOCTL_ARP_TABLE:
		{
			NTSTATUS status = g_original_arp_control(device, irp);

			if (NT_SUCCESS(status))
				RtlZeroMemory(irp->UserBuffer, ioc->Parameters.DeviceIoControl.OutputBufferLength);

			return status;
		}
		}

		return g_original_arp_control(device, irp);
	}

	NTSTATUS my_nic_ioc_handle_PERMANENT(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			n_util::IOC_REQUEST request = *(n_util::PIOC_REQUEST)context;
			ExFreePool(context);

			if (irp->MdlAddress)
			{
				switch (mac_mode)
				{
				case 0:
					n_util::random_string((char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority), 6);
					break;
				case 1:
					RtlCopyMemory((char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority), permanent_mac, 6);
					break;
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
				return request.OldRoutine(device, irp, request.OldContext);
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS my_nic_ioc_handle_CURRENT(PDEVICE_OBJECT device, PIRP irp, PVOID context)
	{
		if (context)
		{
			n_util::IOC_REQUEST request = *(n_util::PIOC_REQUEST)context;
			ExFreePool(context);

			if (irp->MdlAddress)
			{
				switch (mac_mode)
				{
				case 0:
					n_util::random_string((char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority), 6);
					break;
				case 1:
					RtlCopyMemory((char*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority), current_mac, 6);
					break;
				}
			}

			if (request.OldRoutine && irp->StackCount > 1)
				return request.OldRoutine(device, irp, request.OldContext);
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS my_mac_handle_control(PDEVICE_OBJECT device, PIRP irp)
	{
		KIRQL irql;
		KeAcquireSpinLock(&g_lock, &irql);

		for (int i = 0; i < array_size; i++)
		{
			NIC_ARRAY& item = g_nic_array[i];
			if (item.driver_object != device->DriverObject) continue;

			PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
			unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;

			if (code == IOCTL_NDIS_QUERY_GLOBAL_STATS)
			{
				DWORD type = *(PDWORD)irp->AssociatedIrp.SystemBuffer;
				if (type == OID_802_3_PERMANENT_ADDRESS
					|| type == OID_802_5_PERMANENT_ADDRESS)
					n_util::change_ioc(ioc, irp, my_nic_ioc_handle_PERMANENT);
				if (type == OID_802_3_CURRENT_ADDRESS
					|| type == OID_802_5_CURRENT_ADDRESS)
					n_util::change_ioc(ioc, irp, my_nic_ioc_handle_CURRENT);
			}

			KeReleaseSpinLock(&g_lock, irql);

			return item.original_function(device, irp);
		}

		KeReleaseSpinLock(&g_lock, irql);

		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	bool spoofer_nic()
	{
		KeInitializeSpinLock(&g_lock);

		DWORD64 address = 0;
		DWORD32 size = 0;
		if (n_util::get_module_base_address("ndis.sys", address, size) == false) return false;
		n_log::printf("ndis address : %llx \t size : %x \n", address, size);

		PNDIS_FILTER_BLOCK ndis_global_filter_list = (PNDIS_FILTER_BLOCK)n_util::find_pattern_image(address,
			"\x40\x8A\xF0\x48\x8B\x05",
			"xxxxxx");
		if (ndis_global_filter_list == 0) return false;
		n_log::printf("ndis global filter list address : %llx \n", ndis_global_filter_list);

#if (NTDDI_VERSION >= NTDDI_WIN10)
		DWORD64 ndis_filter_block = n_util::find_pattern_image(address,
			"\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33",
			"xx?xx?????x???xxx");
		DWORD offer = 12;
#else (NTDDI_VERSION >= NTDDI_WIN7)
		DWORD64 ndis_filter_block = n_util::find_pattern_image(address,
			"\xF6\x40\x00\x00\x0F\x85\x00\x00\x00\x00\x48\x8B\xA8",
			"xx??xx????xxx");
		DWORD offer = 13;
#endif
		n_log::printf("ndis filter block address : %llx \n", ndis_filter_block);
		if (ndis_filter_block == 0) return false;

		DWORD ndis_filter_block_offset = *(PDWORD)((PBYTE)ndis_filter_block + offer);
		n_log::printf("ndis filter block offset value : %x \n", ndis_filter_block_offset);
		if (ndis_filter_block_offset == 0) return false;


		ndis_global_filter_list = (PNDIS_FILTER_BLOCK)((PBYTE)ndis_global_filter_list + 3);
		ndis_global_filter_list = *(PNDIS_FILTER_BLOCK *)((PBYTE)ndis_global_filter_list + 7 + *(PINT)((PBYTE)ndis_global_filter_list + 3));
		n_log::printf("ndis global filter list address : %llx \n", ndis_global_filter_list);

		for (PNDIS_FILTER_BLOCK filter = ndis_global_filter_list; filter; filter = filter->NextFilter)
		{
			PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK *)((PBYTE)filter + ndis_filter_block_offset);
			if (block == 0) continue;

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
			size_t length = wcslen(filter->FilterInstanceName->Buffer);
#else
			size_t length = filter->Miniport->BaseName.MaximumLength;
#endif
			const unsigned long tag = 'Nics';
			wchar_t* buffer = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, length, tag);
			if (buffer)
			{
				NTSTATUS status = STATUS_FAIL_CHECK;
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
				MM_COPY_ADDRESS addr{ 0 };
				addr.VirtualAddress = filter->FilterInstanceName->Buffer;

				SIZE_T read_size = 0;
				status = MmCopyMemory(buffer, addr, length, MM_COPY_MEMORY_VIRTUAL, &read_size);
				if (status == STATUS_SUCCESS && read_size == length)
#else
				
				if (n_util::SafeReadKrnlAddr(filter->Miniport->BaseName.Buffer, buffer,(unsigned long)length))
#endif
				{
					n_log::printf("ndis InstanceName %S,%llx\n", buffer, length);
					wchar_t* memory = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, length * 4, tag);
					if (memory)
					{
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
						RtlStringCbPrintfW(memory, length * 2, L"\\Device\\%ws", paste_guid(buffer, length));
#else
						NTSTATUS status1 = RtlStringCbPrintfW(memory, length * 4, L"\\Device\\%ws", buffer);
						n_log::printf("ndis RtlStringCbPrintfW %llx\n", status1); 
#endif
						UNICODE_STRING adapter;
						RtlInitUnicodeString(&adapter, memory);

						PFILE_OBJECT file_object = 0;
						PDEVICE_OBJECT device_object = 0;

						status = IoGetDeviceObjectPointer(&adapter, FILE_READ_DATA, &file_object, &device_object);
						if (NT_SUCCESS(status))
						{
							PDRIVER_OBJECT driver_object = device_object->DriverObject;
							n_log::printf("nic adapter %ws\n", driver_object->DriverName.Buffer);

							bool exists = false;
							for (int i = 0; i < array_size; i++)
							{
								n_log::printf("nic g_driver_object %ws\n", g_nic_array[i].driver_object->DriverName.Buffer);
								if (g_nic_array[i].driver_object == driver_object)
								{
									exists = true;
									break;
								}
							}

							if (exists == false)
							{
								g_nic_array[array_size].driver_object = driver_object;
								g_nic_array[array_size].original_function = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
								driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = my_mac_handle_control;
								n_log::printf("nic hook %llx -> %llx \n", g_nic_array[array_size].original_function, my_mac_handle_control);
								array_size++;
							}
							ObDereferenceObject(file_object);
						}
						ExFreePoolWithTag(memory, tag);
					}
				}

				ExFreePoolWithTag(buffer, tag);
			}

			//n_util::random_string((char*)block->ifPhysAddress.Address, block->ifPhysAddress.Length);
			//n_util::random_string((char*)block->PermanentPhysAddress.Address, block->PermanentPhysAddress.Length);
		}

		return true;
	}

	bool start_hook()
	{
		g_original_arp_control = n_util::add_irp_hook(L"\\Driver\\nsiproxy", LgDeviceControlDispatch);
		return g_original_arp_control;
	}

	bool clean_hook()
	{
		KIRQL irql;
		KeAcquireSpinLock(&g_lock, &irql);

		for (int i = 0; i < array_size; i++)
		{
			NIC_ARRAY& item = g_nic_array[i];
			item.driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = item.original_function;
			n_log::printf("clean nic hook %llx -> %llx \n", my_mac_handle_control, item.driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
		}

		KeReleaseSpinLock(&g_lock, irql);

		bool res = n_util::del_irp_hook(L"\\Driver\\nsiproxy", g_original_arp_control);
		return res;
	}
}