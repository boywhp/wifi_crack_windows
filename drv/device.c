/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"

NDIS_STATUS
FilterRegisterDevice(
    VOID
    )
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;
   
    DEBUGP(DL_TRACE, ("==>FilterRegisterDevice\n"));
   
    
    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));
    
    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;
    
    NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);
    
    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));
    
    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);
    
    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);
    
    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &DeviceObject,
                &NdisFilterDeviceHandle
                );
   
   
    if (Status == NDIS_STATUS_SUCCESS)
    {
        FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);
   
        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;

        //
        // Workaround NDIS bug
        //
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }
              
        
    DEBUGP(DL_TRACE, ("<==PtRegisterDevice: %x\n", Status));
        
    return (Status);
        
}

VOID
FilterDeregisterDevice(
    IN VOID
    )

{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

NTSTATUS
FilterDispatch(
    IN PDEVICE_OBJECT       DeviceObject,
    IN PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    
    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS
FilterDeviceIoControl(
    IN PDEVICE_OBJECT        DeviceObject,
    IN PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    ULONG                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    BOOLEAN                     bFalse = FALSE;
    ULONG bytes;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');
    
    Irp->IoStatus.Information = 0;

    InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength; 

    //__debugbreak();

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_FILTER_GET_CHANNEL: 
            {
                    PULONG channel = (PULONG)OutputBuffer;

                    pFilter = filterFindFilterModule(InputBuffer, InputBufferLength);
                    if (pFilter == NULL)
                            break;

                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestQueryInformation,
                                    OID_DOT11_CURRENT_CHANNEL,
                                    channel,
                                    sizeof(ULONG),
                                    0,
                                    0,
                                    &bytes);
                    InfoLength = sizeof(ULONG); // output length
                    DEBUGP(DL_TRACE, ("channel: %x, status: %x\n", *channel, Status));
            }
            break;
        case IOCTL_FILTER_SET_CHANNEL:
            {
                    // CHANNEL(4bytes) + NIC_INTERFACE_NAME
                    if (InputBufferLength < sizeof(ULONG) + 4)
                            break;

                    pFilter = filterFindFilterModule(InputBuffer+4, InputBufferLength-4);
                    if (pFilter == NULL)
                            break;

                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestSetInformation,
                                    OID_DOT11_CURRENT_CHANNEL,
                                    InputBuffer,
                                    sizeof(ULONG),
                                    0,
                                    0,
                                    &bytes);

                    DEBUGP(DL_TRACE, ("WIFI SET CURRENT_CHANNEL: %d %x\n", *(PULONG)InputBuffer, Status));
            }
            break;
        case IOCTL_FILTER_SET_PROMISCUOUS:
            {
                    DOT11_CURRENT_OPERATION_MODE CurrentOperationMode ={0};
                    ULONG filter = NDIS_PACKET_TYPE_ALL_802_11_FILTERS;
                    //NDIS_PACKET_TYPE_ALL_802_11_FILTERS
                    //NDIS_PACKET_TYPE_PROMISCUOUS = NDIS_PACKET_TYPE_802_11_RAW_DATA | NDIS_PACKET_TYPE_802_11_PROMISCUOUS_MGMT;
                    //
                    
                    pFilter = filterFindFilterModule(InputBuffer, InputBufferLength);
                    if (pFilter == NULL)
                            break;

                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestQueryInformation,
                                    OID_DOT11_CURRENT_OPERATION_MODE,
                                    &CurrentOperationMode,
                                    sizeof(DOT11_CURRENT_OPERATION_MODE),
                                    0,
                                    0,
                                    &bytes);
                    if (NT_SUCCESS(Status)){
                            pFilter->Mode = CurrentOperationMode.uCurrentOpMode;
                            DEBUGP(DL_WARN, ("WIFI CURRENT_OPERATION_MODE: %x\n", pFilter->Mode));
                    }

                    /* SET RAW_DATA FILTER */
                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestSetInformation,
                                    OID_GEN_CURRENT_PACKET_FILTER,
                                    &filter,
                                    sizeof(ULONG),
                                    0,
                                    0,
                                    &bytes);

                    DEBUGP(DL_WARN, ("OID_GEN_CURRENT_PACKET_FILTER: %x Status %x\n", filter, Status)); 
            }

            break;
        case IOCTL_FILTER_SET_PHYID:
            {
                    ULONG i, PhyType = 0;
                    UCHAR Buffer[264] = {0};   // 64*4 + 8
                    PDOT11_SUPPORTED_PHY_TYPES SupportPhyTypes = (PDOT11_SUPPORTED_PHY_TYPES)Buffer;

                    if (InputBufferLength < sizeof(ULONG) + 4)
                            break;

                    PhyType = *(PULONG)InputBuffer;
                    pFilter = filterFindFilterModule(InputBuffer+4, InputBufferLength-4);
                    if (pFilter == NULL)
                            break;

                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestQueryInformation,
                                    OID_DOT11_SUPPORTED_PHY_TYPES,
                                    SupportPhyTypes,
                                    sizeof(Buffer),
                                    0,
                                    0,
                                    &bytes);

                    if (SupportPhyTypes->uNumOfEntries >= 64)
                            SupportPhyTypes->uNumOfEntries = 64;
                    
                    for (i = 0; i < SupportPhyTypes->uNumOfEntries; i++){
                            if (SupportPhyTypes->dot11PHYType[i] == (DOT11_PHY_TYPE)PhyType){
                                    //OID_DOT11_DESIRED_PHY_LIST
                                    //OID_DOT11_CURRENT_PHY_ID
                                    //OID_DOT11_POWER_MGMT_REQUEST
                                    //OID_DOT11_AUTO_CONFIG_ENABLED -> e010178
                                    //OID_GEN_CURRENT_PACKET_FILTER -> 1010e 
                                    
                                    Status = filterDoInternalRequest(pFilter,
                                                    NdisRequestSetInformation,
                                                    OID_DOT11_CURRENT_PHY_ID,
                                                    &i,
                                                    sizeof(ULONG),
                                                    0,
                                                    0,
                                                    &bytes);

                                    DEBUGP(DL_WARN, ("OID_DOT11_CURRENT_PHY_ID: %d/%x Status %x\n", i, PhyType, Status)); 
                                    break;
                            }
                    }
            }
            break;

        case IOCTL_FILTER_SET_NICMODE:
            {
                    // MODE(4bytes) + NIC_INTERFACE_NAME
                    DOT11_CURRENT_OPERATION_MODE CurrentOperationMode ={0}; 
                    ULONG OldMode = DOT11_OPERATION_MODE_UNKNOWN;

                    if (InputBufferLength < sizeof(ULONG) + 4)
                            break;

                    pFilter = filterFindFilterModule(InputBuffer+4, InputBufferLength-4);
                    if (pFilter == NULL)
                            break;

                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestQueryInformation,
                                    OID_DOT11_CURRENT_OPERATION_MODE,
                                    &CurrentOperationMode,
                                    sizeof(DOT11_CURRENT_OPERATION_MODE),
                                    0,
                                    0,
                                    &bytes);
                    
                    if (NT_SUCCESS(Status)){
                            OldMode = CurrentOperationMode.uCurrentOpMode;
                            DEBUGP(DL_TRACE, ("WIFI CURRENT_OPERATION_MODE: %x\n", OldMode));
                    }

                    /*
                     * 首先OID_DOT11_DISCONNECT_REQUEST, 然后OID_DOT11_CURRENT_OPERATION_MODE
                     */
                    CurrentOperationMode.uReserved = 0;
                    CurrentOperationMode.uCurrentOpMode = *(PULONG)InputBuffer;

                    if (CurrentOperationMode.uCurrentOpMode == DOT11_OPERATION_MODE_NETWORK_MONITOR){
                            Status = filterDoInternalRequest(pFilter,
                                            NdisRequestSetInformation,
                                            OID_DOT11_DISCONNECT_REQUEST,
                                            NULL,
                                            0,
                                            0,
                                            0,
                                            &bytes);

                            DEBUGP(DL_TRACE, ("OID_DOT11_DISCONNECT_REQUEST: %x\n", Status));
                    }

                    Status = filterDoInternalRequest(pFilter,
                                    NdisRequestSetInformation,
                                    OID_DOT11_CURRENT_OPERATION_MODE,
                                    &CurrentOperationMode,
                                    sizeof(DOT11_CURRENT_OPERATION_MODE),
                                    0,
                                    0,
                                    &bytes);

                    if (NT_SUCCESS(Status)){
                            pFilter->Mode = CurrentOperationMode.uCurrentOpMode;
                            *(PULONG)OutputBuffer = OldMode;
                            InfoLength = sizeof(ULONG);
                            DEBUGP(DL_TRACE, ("DOT11_CURRENT_OPERATION_MODE: %x->%x\n", 
                                                    OldMode,
                                                    pFilter->Mode));
                    }
            }
            break;    
        case IOCTL_FILTER_READ_PACKET:
            {
                    pFilter = filterFindFilterModule(InputBuffer, InputBufferLength);
                    if (pFilter == NULL)
                            break;

                    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
                    
                    if (!IsListEmpty(&pFilter->RcvNBLQueue)){
                            PLIST_ENTRY List = RemoveHeadList(&pFilter->RcvNBLQueue);
                            PFILTER_NB_PACKET Packet = CONTAINING_RECORD(List, FILTER_NB_PACKET, Link);

                            if (OutputBufferLength > Packet->Len && Packet->Len){
                                    NdisMoveMemory(OutputBuffer, 
                                                    Packet->Buffer, 
                                                    Packet->Len);

                                    InfoLength = Packet->Len;
                            }

                            FILTER_FREE_MEM(Packet);
                    }
                    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse); 
            }
            break;
        case IOCTL_FILTER_SEND_PACKET:
            {
                    // BufferLength(ULONG 4bytes) + Buf + NIC_INTERFACE_NAME
                    if (InputBufferLength < 4)
                            break;

                    bytes = *(ULONG*)(InputBuffer);
                    if (bytes <= 0 || bytes + 4 >= InputBufferLength)
                            break;

                    pFilter = filterFindFilterModule(InputBuffer + bytes + 4, 
                                    InputBufferLength - bytes - 4);
                    if (pFilter == NULL)
                            break;

                    FilterSendRawPacket(pFilter, InputBuffer + 4, bytes);

                    DEBUGP(DL_TRACE, ("WIFI SendRawPacket...\n"));
            }
            break;
        case IOCTL_FILTER_RESTART_ALL:
            break;
        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);
            if (pFilter == NULL)
                break;

            NdisFRestartFilter(pFilter->FilterHandle);
            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:
            pInfo = OutputBuffer;
            
            FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
            
            Link = FilterModuleList.Flink;
            
            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
                
                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                        
                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT), 
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);
                            
                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }
                
                Link = Link->Flink;
            }
               
            FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
            if (InfoLength <= OutputBufferLength)
            {
       
                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

             
        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
            

}


PMS_FILTER    
filterFindFilterModule(
    IN PUCHAR                   Buffer,
    IN ULONG                    BufferLength
    )
{

   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   BOOLEAN                  bFalse = FALSE;
   
   FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
               
   Link = FilterModuleList.Flink;
               
   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
               return pFilter;
           }
       }
           
       Link = Link->Flink;
   }
   
   FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
   return NULL;
}




