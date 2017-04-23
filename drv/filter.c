/*++

Copyright (c) 2004-2005  Microsoft Corporation

Module Name:

    Filter.c

Abstract:

    Sample NDIS Lightweight filter driver


Revision History:

    Who         When        What
    --------    --------    ----------------------------------------------

Notes:

--*/

#include "precomp.h"

#define __FILENUMBER    'PNPF'

#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global variables
// 
NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
NDIS_HANDLE         FilterDriverObject;
NDIS_HANDLE         NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT      DeviceObject = NULL;

FILTER_LOCK         FilterListLock;
LIST_ENTRY          FilterModuleList;
PWCHAR              InstanceStrings = NULL;

NDIS_FILTER_PARTIAL_CHARACTERISTICS DefaultChars = {
{ 0, 0, 0},
      0,
      FilterSendNetBufferLists,
      FilterSendNetBufferListsComplete,
      NULL,
      FilterReceiveNetBufferLists,
      FilterReturnNetBufferLists
};    


NTSTATUS 
DriverEntry(
        IN  PDRIVER_OBJECT      DriverObject,
        IN  PUNICODE_STRING     RegistryPath
    )
/*++
 
Routine Description:

    First entry point to be called, when this driver is loaded.
    Register with NDIS as a filter driver.

Arguments:

    DriverObject - pointer to the system's driver object structure
                   for this driver

    RegistryPath - system's registry path for this driver

Return Value:

    STATUS_SUCCESS if all initialization is successful, STATUS_XXX
    error code if not.

--*/

{
    NDIS_STATUS                             Status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS      FChars;
    NDIS_STRING                             ServiceName;
    NDIS_STRING                             UniqueName;
    NDIS_STRING                             FriendlyName;
    BOOLEAN                                    bFalse = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);
    
    DEBUGP(DL_TRACE,("===>DriverEntry...\n"));
   
    RtlInitUnicodeString(&ServiceName, FILTER_SERVICE_NAME);
    RtlInitUnicodeString(&FriendlyName, FILTER_FRIENDLY_NAME);
    RtlInitUnicodeString(&UniqueName, FILTER_UNIQUE_NAME);
    FilterDriverObject = DriverObject;
    
    do
    {
        NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
        FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
        FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
        FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
        FChars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
        FChars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
        FChars.MajorDriverVersion = 1;
        FChars.MinorDriverVersion = 0;
        FChars.Flags = 0;

        FChars.FriendlyName = FriendlyName;
        FChars.UniqueName = UniqueName;
        FChars.ServiceName = ServiceName;

        //
        // for the time being, there is no additional options to register
        // but let's have this handler anyway
        //
        FChars.SetOptionsHandler = FilterRegisterOptions;        
        FChars.AttachHandler = FilterAttach;
        FChars.DetachHandler = FilterDetach;
        FChars.RestartHandler = FilterRestart;
        FChars.PauseHandler = FilterPause;
        FChars.SetFilterModuleOptionsHandler = FilterSetModuleOptions;           
        FChars.OidRequestHandler = FilterOidRequest;
        FChars.OidRequestCompleteHandler = FilterOidRequestComplete;
        FChars.CancelOidRequestHandler = FilterCancelOidRequest;
        
        FChars.SendNetBufferListsHandler = FilterSendNetBufferLists;        
        FChars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
        FChars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
        FChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
        FChars.DevicePnPEventNotifyHandler = FilterDevicePnPEventNotify;
        FChars.NetPnPEventHandler = FilterNetPnPEvent;
        FChars.StatusHandler = FilterStatus;
        FChars.CancelSendNetBufferListsHandler = FilterCancelSendNetBufferLists;
      
        DriverObject->DriverUnload = FilterUnload;
    
        FilterDriverHandle = NULL;

        FILTER_INIT_LOCK(&FilterListLock);

        InitializeListHead(&FilterModuleList);
        
        Status = NdisFRegisterFilterDriver(DriverObject,
                                           (NDIS_HANDLE)FilterDriverObject,
                                           &FChars, 
                                           &FilterDriverHandle);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, ("MSFilter: Register filter driver failed.\n")); 
            break;
        }
        //
        // Initilize spin locks
        //

        Status = FilterRegisterDevice();

        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisFDeregisterFilterDriver(FilterDriverHandle);
            FILTER_FREE_LOCK(&FilterListLock);
            DEBUGP(DL_WARN, ("MSFilter: Register device for the filter driver failed.\n")); 
            break;
        }

        
    } 
    while(bFalse);
    
    
    DEBUGP(DL_TRACE, ("<===DriverEntry, Status = %8x\n", Status));
    return Status;
    
}


NDIS_STATUS
FilterRegisterOptions(
        IN NDIS_HANDLE  NdisFilterDriverHandle,
        IN NDIS_HANDLE  FilterDriverContext
        )
{
    DEBUGP(DL_TRACE, ("===>FilterRegisterOptions\n"));
    
    ASSERT(NdisFilterDriverHandle == FilterDriverHandle);
    ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

    if ((NdisFilterDriverHandle != (NDIS_HANDLE)FilterDriverHandle) ||
        (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject))
    {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    DEBUGP(DL_TRACE, ("<===FilterRegisterOptions\n"));

    return (NDIS_STATUS_SUCCESS);
}

    
NDIS_STATUS
FilterAttach(
    IN  NDIS_HANDLE                     NdisFilterHandle,
    IN  NDIS_HANDLE                     FilterDriverContext,
    IN  PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
    )
/*++

Routine Description:

    Filter attach routine.
    Create filter's context, and allocate NetBufferLists and NetBuffers pools and any 
    other resources, read configuration if needed.

Arguments:

    NdisFilterHandle - Specify a handle identifying this instance of the filter. FilterAttach
                       should save this handle. It is a required  parameter in subsequent calls
                       to NdisFxxx functions.
    FilterDriverContext - Filter driver context passed to NdisFRegisterFilterDriver.

    AttachParameters - attach parameters

Return Value:

    NDIS_STATUS_SUCCESS: FilterAttach successfully allocated and initialize data structures
                         for this filter instance.
    NDIS_STATUS_RESOURCES: FilterAttach failed due to insufficient resources.
    NDIS_STATUS_FAILURE: FilterAttach could not set up this instance of this fitler and it has called
                         NDisWriteErrorLogEntry with parameters spedifying the reason for failure.
                         
NOTE: Called at PASSIVE_LEVEL

    FILTER can use NdisRegisterDeviceEx to create a device, so the upper layer can send Irps to the filter.
--*/
{
    PMS_FILTER              pFilter = NULL;
    NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
    NDIS_FILTER_ATTRIBUTES  FilterAttributes;
    NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
    ULONG                   Size;
    BOOLEAN               bFalse = FALSE;
    
    DEBUGP(DL_TRACE, ("===>FilterAttach: NdisFilterHandle %p\n", NdisFilterHandle));

    do
    {
        ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
        if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
        {
            Status = NDIS_STATUS_INVALID_PARAMETER;
            break;
        }
        
        if (AttachParameters->MiniportMediaType != NdisMediumNative802_11)
        {
           DEBUGP(DL_ERROR, ("MSFilter: Doesn't support media type other than NdisMedium802_11.\n")); 
        
           Status = NDIS_STATUS_INVALID_PARAMETER;
           break;
        }
        
        Size = sizeof(MS_FILTER) + 
               AttachParameters->FilterModuleGuidName->Length + 
               AttachParameters->BaseMiniportInstanceName->Length + 
               AttachParameters->BaseMiniportName->Length;
        
        pFilter = (PMS_FILTER)FILTER_ALLOC_MEM(NdisFilterHandle, Size);
        if (pFilter == NULL)
        {
            DEBUGP(DL_WARN, ("MSFilter: Failed to allocate context structure.\n"));
            Status = NDIS_STATUS_RESOURCES;
            break;
        }
        
        NdisZeroMemory(pFilter, sizeof(MS_FILTER));

        pFilter->FilterModuleName.Length = pFilter->FilterModuleName.MaximumLength = AttachParameters->FilterModuleGuidName->Length;
        pFilter->FilterModuleName.Buffer = (PWSTR)((PUCHAR)pFilter + sizeof(MS_FILTER));
        NdisMoveMemory(pFilter->FilterModuleName.Buffer, 
                        AttachParameters->FilterModuleGuidName->Buffer,
                        pFilter->FilterModuleName.Length);


        
        pFilter->MiniportFriendlyName.Length = pFilter->MiniportFriendlyName.MaximumLength = AttachParameters->BaseMiniportInstanceName->Length;
        pFilter->MiniportFriendlyName.Buffer = (PWSTR)((PUCHAR)pFilter->FilterModuleName.Buffer + pFilter->FilterModuleName.Length);
        NdisMoveMemory(pFilter->MiniportFriendlyName.Buffer, 
                        AttachParameters->BaseMiniportInstanceName->Buffer,
                        pFilter->MiniportFriendlyName.Length);

        
        pFilter->MiniportName.Length = pFilter->MiniportName.MaximumLength = AttachParameters->BaseMiniportName->Length;
        pFilter->MiniportName.Buffer = (PWSTR)((PUCHAR)pFilter->MiniportFriendlyName.Buffer + 
                                                   pFilter->MiniportFriendlyName.Length);
        NdisMoveMemory(pFilter->MiniportName.Buffer, 
                        AttachParameters->BaseMiniportName->Buffer,
                        pFilter->MiniportName.Length);

        pFilter->MiniportIfIndex = AttachParameters->BaseMiniportIfIndex;
        //
        // The filter should intialize NoTrackRecieves and NoTrackSends properly, for this
        // driver, since its default characteristic has both send and receive handler, they
        // are initiazed to FALSE.
        //
        pFilter->TrackReceives = TRUE;
        pFilter->TrackSends = TRUE;
        pFilter->FilterHandle = NdisFilterHandle;

        InitializeListHead(&pFilter->RcvNBLQueue);
        

        NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));

        PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        PoolParameters.Header.Size = sizeof(PoolParameters);
        PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_TCP_IP ;
        PoolParameters.fAllocateNetBuffer = TRUE;
        PoolParameters.PoolTag = FILTER_TAG;

        pFilter->FilterNblPool = NdisAllocateNetBufferListPool(NdisFilterHandle, &PoolParameters);

        NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
        FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
        FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
        FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
        FilterAttributes.Flags = 0;

        Status = NdisFSetAttributes(NdisFilterHandle, 
                                    pFilter,
                                    &FilterAttributes);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, ("MSFilter: Failed to set attributes.\n"));
            break;
        }
        
        pFilter->State = FilterPaused;

        FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
        InsertHeadList(&FilterModuleList, &pFilter->FilterModuleLink);
        FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

    }
    while (bFalse);
    
    if (Status != NDIS_STATUS_SUCCESS)
    {
        if (pFilter != NULL)
        {
            FILTER_FREE_MEM(pFilter);
        }
    }
    
    DEBUGP(DL_TRACE, ("<===FilterAttach:    Status %x\n", Status));
    return Status;
}

NDIS_STATUS
FilterPause(
        IN  NDIS_HANDLE                     FilterModuleContext,
        IN  PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
        )
/*++
 
Routine Description:

    Filter pause routine.
    Complete all the outstanding sends and queued sends,
    Waiting for all the outstanding recvs to be returned 
    and return all the queued receives

Arguments:

    FilterModuleContext - pointer to the filter context stucture.

Return Value:

    STATUS_SUCCESS if filter pauses successful, STATUS_PENDING
    if not.

NOTE: when the filter is in pause state, it can still process requests, complete sending,
    and returning packets to the lower filter, and also indicate status.
    Called at PASSIVE_LEVEL
      
--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)(FilterModuleContext);
    NDIS_STATUS         Status;
    BOOLEAN               bFalse = FALSE;

    UNREFERENCED_PARAMETER(PauseParameters);
    
    DEBUGP(DL_TRACE, ("===>NDISLWF FilterPause: FilterInstance %p\n", FilterModuleContext));

    //
    // Set the flag that the filter is going to pause
    // 
    FILTER_ASSERT(pFilter->State == FilterRunning); 
    
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    pFilter->State = FilterPausing;
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);


    Status = NDIS_STATUS_SUCCESS;    

    pFilter->State = FilterPaused;
    
    DEBUGP(DL_TRACE, ("<===FilterPause:  Status %x\n", Status));
    return Status;
}

NDIS_STATUS
FilterRestart(
    IN  NDIS_HANDLE                     FilterModuleContext,
    IN  PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
    )
/*++

Routine Description:
 
    Filter restart routine.
    Restart the filter

Arguments:

    FilterModuleContext - pointer to the filter context stucture.

Return Value:

    NDIS_STATUS_SUCCESS: if filter restarts successfully
    NDIS_STATUS_XXX: Otherwise.


NOTE: called at PASSIVE_LEVEL

--*/
{
    NDIS_STATUS     Status;
    PMS_FILTER      pFilter = (PMS_FILTER)FilterModuleContext; // BUGBUG, the cast may be wrong
    NDIS_HANDLE     ConfigurationHandle = NULL;


    PNDIS_RESTART_GENERAL_ATTRIBUTES NdisGeneralAttributes;
    PNDIS_RESTART_ATTRIBUTES         NdisRestartAttributes;
    NDIS_CONFIGURATION_OBJECT        ConfigObject;
    
    DEBUGP(DL_TRACE, ("===>FilterRestart:   FilterModuleContext %p\n", FilterModuleContext));
    
    FILTER_ASSERT(pFilter->State == FilterPaused);

    ConfigObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    ConfigObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    ConfigObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    ConfigObject.NdisHandle = FilterDriverHandle;
    ConfigObject.Flags = 0;
    
    Status = NdisOpenConfigurationEx(&ConfigObject, &ConfigurationHandle);
    if (Status != NDIS_STATUS_SUCCESS)
    {        
        //
        // Filter driver can choose to fail the restart if it cannot open the configuration
        //

#if 0
        //
        // The code is here just to demonstrate how to call NDIS to write an eventlog. If drivers need to write 
        // an event log.
        //
        PWCHAR              ErrorString = L"Ndislwf";
        
        DEBUGP(DL_WARN, ("FilterRestart: Cannot open configuration.\n"));
        NdisWriteEventLogEntry(FilterDriverObject,
                                EVENT_NDIS_DRIVER_FAILURE,
                                0,
                                1,
                                &ErrorString,
                                sizeof(Status),
                                &Status);
#endif                                
                                
    }


    if (Status == NDIS_STATUS_SUCCESS)
    {
        NdisCloseConfiguration(ConfigurationHandle);
    }

    NdisRestartAttributes = RestartParameters->RestartAttributes;

    //
    // If NdisRestartAttributes is not NULL, then miniport can modify generic attributes and add
    // new media specific info attributes at the end. Otherwise, NDIS restarts the miniport because 
    // of other reason, miniport should not try to modify/add attributes
    //
    if (NdisRestartAttributes != NULL)
    {
        PNDIS_RESTART_ATTRIBUTES   NextAttributes;
        
        ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);
    
        NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;
    
        //
        // Check to see if we need to change any attributes, for example, the driver can change the current
        // MAC address here. Or the driver can add media specific info attributes.
        //
        NdisGeneralAttributes->LookaheadSize = 128;

        //
        // Check the next attributes to see whether the filter need to modify
        //
        NextAttributes = NdisRestartAttributes->Next;

        while (NextAttributes != NULL)
        {
            //
            // If somehow the filter needs to change a attributes which requires more space then
            // the current attributes:
            // 1. Remove the attribute from the Attributes list: 
            //    TempAttributes = NextAttributes;
            //    NextAttributes = NextAttributes->Next;
            // 2. Free the memory for the current attributes: NdisFreeMemory(TempAttributes, 0 , 0);
            // 3. Dynamically allocate the memory for the new attributes by calling 
            //    NdisAllocateMemoryWithTagPriority: 
            //    NewAttributes = NdisAllocateMemoryWithTagPriority(Handle, size, Priority);
            // 4. Fill in the new attribute
            // 5. NewAttributes->Next = NextAttributes;
            // 6. NextAttributes = NewAttributes; // Just to make the next statement works.
            //
            NextAttributes = NextAttributes->Next;
        }

        //
        // Add a new attributes at the end
        // 1. Dynamically allocate the memory for the new attributes by calling 
        //    NdisAllocateMemoryWithTagPriority.
        // 2. Fill in the new attribute
        // 3. NextAttributes->Next = NewAttributes;
        // 4. NewAttributes->Next = NULL;
        
        
        
    }

    //
    // If everything is OK, set the filter in running state
    // If it get preempted, it doesn't matter 
    //
    pFilter->State = FilterRunning; // when successful


    Status = NDIS_STATUS_SUCCESS;
    
    if (Status != NDIS_STATUS_SUCCESS)
    {
        pFilter->State = FilterPaused;
    }
    
    
    DEBUGP(DL_TRACE, ("<===FilterRestart:  FilterModuleContext %p, Status %x\n", FilterModuleContext, Status));
    return Status;
}


VOID
FilterDetach(
        IN  NDIS_HANDLE     FilterModuleContext
        )
/*++

Routine Description:

    Filter detach routine.
    This is a required function that will deallocate all the resources allocated during
    FitlerAttach. NDIS calls FilterAttachto remove a filter instance from a fitler stack.

Arguments:

    FilterModuleContext - pointer to the filter context area.

Return Value:
    None.

NOTE: Called at PASSIVE_LEVEL and the filter is in paused state

--*/
{
    PMS_FILTER                  pFilter = (PMS_FILTER)FilterModuleContext;
    BOOLEAN                     bFalse = FALSE;


    DEBUGP(DL_TRACE, ("===>FilterDetach:    FilterInstance %p\n", FilterModuleContext));


    //
    // Filter must be in paused state
    // 
    FILTER_ASSERT(pFilter->State == FilterPaused);

    //
    // Free filter RcvNBLQueue 
    //
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    while (!IsListEmpty(&pFilter->RcvNBLQueue)){
            PLIST_ENTRY List = RemoveHeadList(&pFilter->RcvNBLQueue);
            PFILTER_NB_PACKET Packet = CONTAINING_RECORD(List, FILTER_NB_PACKET, Link);
            
            FILTER_FREE_MEM(Packet);
    }
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

    //
    // Don't come up anything that would prevent the filter from detaching
    //
    
    //
    // Free filter instance name if allocated.
    //
    if (pFilter->FilterName.Buffer != NULL)
    {
        FILTER_FREE_MEM(pFilter->FilterName.Buffer);
    }

    FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
    RemoveEntryList(&pFilter->FilterModuleLink);
    FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

    NdisFreeNetBufferListPool(pFilter->FilterNblPool);
    //
    // Free the memory allocated
    FILTER_FREE_MEM(pFilter);

    //
    // Alway return success
    //
    DEBUGP(DL_TRACE, ("<===FilterDetach Successfully\n"));
    
    return;
}

VOID
FilterUnload(
        IN  PDRIVER_OBJECT      DriverObject
        )
/*++

Routine Description:

    Filter driver's unload routine.
    Deregister the driver from NDIS

Arguments:

    DriverObject - pointer to the system's driver object structure
                   for this driver

Return Value:

    NONE
 
--*/
{
#if DBG    
    BOOLEAN               bFalse = FALSE;
#endif

    UNREFERENCED_PARAMETER(DriverObject);

    DEBUGP(DL_TRACE, ("===>FilterUnload\n"));
    
    //
    // Should free the filter context list
    // 
    FilterDeregisterDevice();
    NdisFDeregisterFilterDriver(FilterDriverHandle);
    
#if DBG    
    FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
    ASSERT(IsListEmpty(&FilterModuleList));

    FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
    
#endif    
    
    FILTER_FREE_LOCK(&FilterListLock);
    
    DEBUGP(DL_TRACE, ("<===FilterUnload\n"));

    return;
    
}

NDIS_STATUS
FilterOidRequest(
        IN  NDIS_HANDLE         FilterModuleContext,
        IN  PNDIS_OID_REQUEST   Request
        )

/*++

Routine Description:

    Request handler 
    Handle requests from upper layers

Arguments:

    FilterModuleContext: Pointer to out filter
    Request: Pointer to request passed down
   

Return Value:

     NDIS_STATUS_SUCCESS
     NDIS_STATUS_PENDING
     NDIS_STATUS_XXX

NOTE: Called at <= DISPATCH_LEVEL      
 
--*/
{
    PMS_FILTER              pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_STATUS             Status;
    PNDIS_OID_REQUEST       ClonedRequest=NULL;
    BOOLEAN                 bSubmitted = FALSE;
    PFILTER_REQUEST_CONTEXT Context;
    BOOLEAN               bFalse = FALSE;

    
    DEBUGP(DL_TRACE, ("===>FilterOidRequest: Request %p.\n", Request));

    /*
    if (Request->RequestType == NdisRequestSetInformation){
            DEBUGP(DL_WARN, ("===>FilterOidRequest: SetInformation Oid %x %d bytes\n", 
                                    Request->DATA.SET_INFORMATION.Oid,
                                    Request->DATA.SET_INFORMATION.InformationBufferLength));
    }
    */

    do
    {
        Status = NdisAllocateCloneOidRequest(pFilter->FilterHandle,
                                            Request,
                                            FILTER_TAG,
                                            &ClonedRequest);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, ("FilerOidRequest: Cannot Clone Request\n"));
            break;
        }

        Context = (PFILTER_REQUEST_CONTEXT)(&ClonedRequest->SourceReserved[0]);
        *Context = Request;

        bSubmitted = TRUE;

        //
        // Use same request ID
        //
        ClonedRequest->RequestId = Request->RequestId;

        pFilter->PendingOidRequest = ClonedRequest;


        Status = NdisFOidRequest(pFilter->FilterHandle, ClonedRequest);

        if (Status != NDIS_STATUS_PENDING)
        {


            FilterOidRequestComplete(pFilter, ClonedRequest, Status);
            Status = NDIS_STATUS_PENDING;
        } 

        
    }while (bFalse);

    if (bSubmitted == FALSE)
    {
        switch(Request->RequestType)
        {
            case NdisRequestMethod:
                Request->DATA.METHOD_INFORMATION.BytesRead = 0;
                Request->DATA.METHOD_INFORMATION.BytesNeeded = 0; 
                Request->DATA.METHOD_INFORMATION.BytesWritten = 0; 
                break;

            case NdisRequestSetInformation:
                Request->DATA.SET_INFORMATION.BytesRead = 0;
                Request->DATA.SET_INFORMATION.BytesNeeded = 0; 
                break;

            case NdisRequestQueryInformation:
            case NdisRequestQueryStatistics:
            default:
                Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
                Request->DATA.QUERY_INFORMATION.BytesNeeded = 0; 
                break;
        }

    }
    DEBUGP(DL_TRACE, ("<===FilterOidRequest: Status %8x.\n", Status));

    return Status;

}

VOID
FilterCancelOidRequest(
    IN  NDIS_HANDLE             FilterModuleContext,
    IN  PVOID                   RequestId
    )
{
    PMS_FILTER                          pFilter = (PMS_FILTER)FilterModuleContext;
    PNDIS_OID_REQUEST                   Request = NULL;
    PFILTER_REQUEST_CONTEXT             Context;
    PNDIS_OID_REQUEST                   OriginalRequest = NULL;
    BOOLEAN               bFalse = FALSE;
     
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    
    Request = pFilter->PendingOidRequest;

    if (Request != NULL)
    {
        Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
    
        OriginalRequest = (*Context);
    }

    if ((OriginalRequest != NULL) && (OriginalRequest->RequestId == RequestId))
    {
        FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
        
        NdisFCancelOidRequest(pFilter->FilterHandle, RequestId);
    }
    else
    {
        FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
    }
        

}

    
VOID
FilterOidRequestComplete(
        IN  NDIS_HANDLE         FilterModuleContext,
        IN  PNDIS_OID_REQUEST   Request,
        IN  NDIS_STATUS         Status
        )
/*++

Routine Description:

    Same operation we need to do when outstanding request are completed

Arguments:

    FilterModuleContext -- Pointer to the filter context area
    NdisRequest - The request to complete
    Status - The completion status
  
Return Value:

    NONE
 
--*/
{
    PMS_FILTER                          pFilter = (PMS_FILTER)FilterModuleContext;
    PNDIS_OID_REQUEST                   OriginalRequest;
    PFILTER_REQUEST_CONTEXT             Context;
    BOOLEAN               bFalse = FALSE;
    
    DEBUGP(DL_TRACE, ("===>FilterOidRequestComplete, Request %p.\n", Request));

    Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
    OriginalRequest = (*Context);

    //
    // This is the internal request
    //
    if (OriginalRequest == NULL)
    {
        filterInternalRequestComplete(pFilter, Request, Status);
        return;
    }


    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    
    ASSERT(pFilter->PendingOidRequest == Request);
    pFilter->PendingOidRequest = NULL;

    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);


    //
    // Copy the information from the returned request to the original request
    //
    switch(Request->RequestType)
    {
        case NdisRequestMethod:
            OriginalRequest->DATA.METHOD_INFORMATION.OutputBufferLength =  Request->DATA.METHOD_INFORMATION.OutputBufferLength;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesRead = Request->DATA.METHOD_INFORMATION.BytesRead;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesNeeded = Request->DATA.METHOD_INFORMATION.BytesNeeded; 
            OriginalRequest->DATA.METHOD_INFORMATION.BytesWritten = Request->DATA.METHOD_INFORMATION.BytesWritten; 
            break;

        case NdisRequestSetInformation:  
            OriginalRequest->DATA.SET_INFORMATION.BytesRead = Request->DATA.SET_INFORMATION.BytesRead;
            OriginalRequest->DATA.SET_INFORMATION.BytesNeeded = Request->DATA.SET_INFORMATION.BytesNeeded; 
            break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
        default:     
            OriginalRequest->DATA.QUERY_INFORMATION.BytesWritten = Request->DATA.QUERY_INFORMATION.BytesWritten;
            OriginalRequest->DATA.QUERY_INFORMATION.BytesNeeded = Request->DATA.QUERY_INFORMATION.BytesNeeded;
            break;
    }


    (*Context) = NULL;

    NdisFreeCloneOidRequest(pFilter->FilterHandle, Request);

    NdisFOidRequestComplete(pFilter->FilterHandle, OriginalRequest, Status);
    
    DEBUGP(DL_TRACE, ("<===FilterOidRequestComplete.\n"));
}


VOID
FilterStatus(
        IN  NDIS_HANDLE             FilterModuleContext,
        IN  PNDIS_STATUS_INDICATION StatusIndication
        )
/*++

Routine Description:

    Indicate Status Handle

Arguments:
 
    FilterModuleContext: Pointer to our filter 
    GeneralStatus: 
    StatusBuffer:
    StatusBufferSize:
   
Return Value:

    NONE
NOTE: called at <= DISPATCH_LEVEL     
 
  FILTER driver may call NdisFIndicateStatus to generate status indication to all higher layer modules.
  
--*/
{
    PMS_FILTER              pFilter = (PMS_FILTER)FilterModuleContext;
#if DBG    
    BOOLEAN                  bFalse = FALSE;
#endif

    DEBUGP(DL_TRACE, ("===>FilterStaus, IndicateStatus = %8x.\n", StatusIndication->StatusCode));
   
#if DBG
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    ASSERT(pFilter->bIndicating == FALSE);
    pFilter->bIndicating = TRUE;
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
#endif    
    
    
    // Now, No status need to handle by the filter. May get one later
    //
    NdisFIndicateStatus(pFilter->FilterHandle, StatusIndication);

#if DBG    
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    ASSERT(pFilter->bIndicating == TRUE);
    pFilter->bIndicating = FALSE;
    
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);


#endif
    
    DEBUGP(DL_TRACE, ("<===FilterStaus.\n"));

}

VOID
FilterDevicePnPEventNotify(
        IN  NDIS_HANDLE             FilterModuleContext,
        IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
        )
/*++

Routine Description:

    FilterPnpEvent handler
 
Arguments:

    FilterModuleContext: Pointer to our filter
    NetPnPEvent: Pointer to an PnP event
  
Return Value:

     NONE

NOTE: called at PASSIVE_LEVEL      
  
--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_DEVICE_PNP_EVENT   DevicePnPEvent = NetDevicePnPEvent->DevicePnPEvent;
#if DBG
    BOOLEAN             bFalse = FALSE;
#endif

    DEBUGP(DL_TRACE, ("===>FilterDevicePnPEventNotify: NetPnPEvent = %p.\n", NetDevicePnPEvent));

    switch (DevicePnPEvent)
    {

        case NdisDevicePnPEventQueryRemoved: 
        case NdisDevicePnPEventRemoved:
        case NdisDevicePnPEventSurpriseRemoved:
        case NdisDevicePnPEventQueryStopped:
        case NdisDevicePnPEventStopped:
        case NdisDevicePnPEventPowerProfileChanged:
        case NdisDevicePnPEventFilterListChanged:
                
            break;
            
        default:
            DEBUGP(DL_ERROR, ("FilterDevicePnPEventNotify: Invalid event.\n"));
            FILTER_ASSERT(bFalse);
            
            break;
    }

    NdisFDevicePnPEventNotify(pFilter->FilterHandle, NetDevicePnPEvent);
                              
    DEBUGP(DL_TRACE, ("<===FilterDevicePnPEventNotify\n"));

}


NDIS_STATUS
FilterNetPnPEvent(
        IN  NDIS_HANDLE             FilterModuleContext,
        IN  PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification
        )
{
    PMS_FILTER                pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_STATUS               Status = NDIS_STATUS_SUCCESS;

    Status = NdisFNetPnPEvent(pFilter->FilterHandle, NetPnPEventNotification);
    
    return Status;
}

VOID
FilterSendNetBufferListsComplete(
        IN  NDIS_HANDLE         FilterModuleContext,
        IN  PNET_BUFFER_LIST    NetBufferLists,
        IN  ULONG               SendCompleteFlags
        )
/*++
 
Routine Description:

    SendNetBufferListComplete 

Arguments:

      
     
Return Value:

     NONE
 
--*/
{
    PMS_FILTER         pFilter = (PMS_FILTER)FilterModuleContext;
    ULONG              NumOfSendCompletes = 0;
    BOOLEAN            DispatchLevel;
    PNET_BUFFER_LIST   CurrNbl,NextNbl,LastNbl = NULL;
    PNET_BUFFER_LIST   PassthruNbl = NULL;
   
    DEBUGP(DL_TRACE, ("===>SendNBLComplete, NetBufferList: %p.\n", NetBufferLists));

    //
    // if necessary, undo any modifications to the NetBufferList thate were performed "on the way down"
    //
    if (pFilter->TrackSends)
    {
        for (CurrNbl = NetBufferLists; CurrNbl; CurrNbl = NextNbl) {
                NumOfSendCompletes++;
                NextNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);

                if (CurrNbl->NdisPoolHandle == pFilter->FilterNblPool) {       
                        FilterFreeNdisNBL(CurrNbl);
                } else {
                        if (PassthruNbl == NULL)
                                PassthruNbl = CurrNbl;
                        
                        if (LastNbl)
                                NET_BUFFER_LIST_NEXT_NBL(LastNbl) = CurrNbl;

                        LastNbl = CurrNbl;
                        NET_BUFFER_LIST_NEXT_NBL(CurrNbl) = NULL;
                }
        }
        DispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendCompleteFlags);
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
        pFilter->OutstandingSends -= NumOfSendCompletes;
        FILTER_LOG_SEND_REF(2, pFilter, PrevNbl, pFilter->OutstandingSends);        
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
    }

    if (PassthruNbl){
        NdisFSendNetBufferListsComplete(pFilter->FilterHandle, 
                        PassthruNbl, 
                        SendCompleteFlags);
    }

    DEBUGP(DL_TRACE, ("<===SendNBLComplete.\n"));
}

PNET_BUFFER_LIST FilterAllocNdisNBL(PMS_FILTER pFilter, ULONG DataLength, PUCHAR *ppDataBuffer)
{
        PMDL pMdl;
        PUCHAR pDataBuffer = NULL;
        PNET_BUFFER_LIST pNetBufList;
 
        NdisAllocateMemoryWithTag(&pDataBuffer, DataLength, FILTER_ALLOC_TAG);
        if (pDataBuffer == NULL) {
                DEBUGP(DL_WARN, ("WARN:FilterAllocNdisNBL alloc memory failed!\n"));
                return NULL;
        }

        pMdl = IoAllocateMdl(pDataBuffer, DataLength, 0, 0, 0);
        if (pMdl == NULL) {
                DEBUGP(DL_WARN, ("WARN:FilterAllocNdisNBL alloc mdl failed!\n"));
                NdisFreeMemory(pDataBuffer, 0, 0);
                return NULL;
        }

        MmBuildMdlForNonPagedPool(pMdl);
        pMdl->Next = NULL;

        pNetBufList = NdisAllocateNetBufferAndNetBufferList(
                        pFilter->FilterNblPool,
                        0,                              // ContextSize
                        0,                              // ContextBackfill
                        pMdl,                    // MdlChain
                        0,                              // DataOffset
                        DataLength);                   // DataLength

        if (pNetBufList == NULL) {
                DEBUGP(DL_WARN, ("WARN:AllocNdisNBL alloc nbl failed!\n"));
                NdisFreeMdl(pMdl);
                NdisFreeMemory(pDataBuffer, 0, 0);
                return NULL;
        }

        NBL_SET_PROT_RSVD_FLAG(pNetBufList, FILTER_NBL_FLAG);
        *ppDataBuffer = pDataBuffer;

        return pNetBufList;
}

VOID FilterFreeNdisNBL(PNET_BUFFER_LIST pNetBufferList)
{
        PMDL pMdl = NULL;
        ULONG TotalLength;
        UINT BufferLength;
        PUCHAR pCopyData = NULL;

        if (!NBL_TEST_PROT_RSVD_FLAG(pNetBufferList, FILTER_NBL_FLAG)) 
                return;

        pMdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(pNetBufferList));
        TotalLength = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(pNetBufferList));

        NdisQueryMdl(pMdl, (PVOID *)&pCopyData, &BufferLength, NormalPagePriority);

        if (BufferLength != TotalLength || !pMdl || !pCopyData) {
                DEBUGP(DL_ERROR, ("WARN:FilterFreeNdisNBL Buffer ERROR!\n"));
                return;
        }

        NdisFreeNetBufferList(pNetBufferList);
        NdisFreeMdl(pMdl);
        NdisFreeMemory(pCopyData, 0, 0);
}

NDIS_NBL_MEDIA_SPECIFIC_INFORMATION DamnNblMediaInfo;
DOT11_EXTSTA_SEND_CONTEXT NblMediaInfo;

VOID
FilterSendRawPacket(PMS_FILTER pFilter, PVOID Buffer, ULONG Size)
{
        PUCHAR NblBuf = NULL;
        PNET_BUFFER_LIST NetBufferLists;

        NetBufferLists = FilterAllocNdisNBL(pFilter, Size, &NblBuf);
        if (NetBufferLists && NblBuf) {
                NdisMoveMemory(NblBuf, Buffer, Size);

                //__debugbreak();

                // RTL8187驱动会查询该信息，否则BSOD
                DamnNblMediaInfo.Tag = 0;

                /*
                 * DOT11_EXTSTA_SEND_CONTEXT 
                 * https://msdn.microsoft.com/en-us/library/windows/hardware/ff548632(v=vs.85).aspx
                 */
                NblMediaInfo.Header.Revision = DOT11_EXTSTA_SEND_CONTEXT_REVISION_1;
                NblMediaInfo.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
                NblMediaInfo.Header.Size = sizeof(DOT11_EXTSTA_SEND_CONTEXT);

                NblMediaInfo.usExemptionActionType = DOT11_EXEMPT_ALWAYS;
                NblMediaInfo.uPhyId = DOT11_PHY_ID_ANY;
                NblMediaInfo.pvMediaSpecificInfo = NULL;
                NblMediaInfo.uDelayedSleepValue = 0;
                NblMediaInfo.uSendFlags = 0;

                NET_BUFFER_LIST_INFO(NetBufferLists, MediaSpecificInformation) = &NblMediaInfo;

                NdisFSendNetBufferLists(pFilter->FilterHandle, NetBufferLists, 0, 0);
        }
}

VOID
FilterSendNetBufferLists(
        IN  NDIS_HANDLE         FilterModuleContext,
        IN  PNET_BUFFER_LIST    NetBufferLists,
        IN  NDIS_PORT_NUMBER    PortNumber,
        IN  ULONG               SendFlags
        )
/*++
 
Routine Description:

    Send Net Buffer List handler
    This function is an optional function for filter drivers. If provided, NDIS
    will call this function to transmit a linked list of NetBuffers, described by a 
    NetBuferList, over the network. If this handler is NULL, NDIS will skip calling
    this fitler when sending a NetBufferList and will call the next lower fitler 
    in the stack with a non_NULL FilterSendNetBufferList handleror the miniport driver.
    A filter that doesn't provide a FilerSendNetBufferList handler can not initiate a 
    send o its own.

Arguments:

    FilterModuleContext: Pointer to our filter context area.
    NetBufferLists: Pointer to a List of NetBufferLists.
    PortNumber - Port Number to which this send is targetted
    SendFlags-  Specifies if the call is at DISPATCH_LEVEL                     
  

Return Value:
 
    NDIS_STATUS_SUCCESS: 
    NDIS_STATUS_PENDING:
    NDIS_STATUS_INVALID_PACKET:
    NDIS_STATUS_RESOURCES:
    NDIS_STATUS_FAILURE:


NOTE: The filter will act like a passthru filter.       
 
--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    PNET_BUFFER_LIST    CurrNbl;
    BOOLEAN             DispatchLevel;
    BOOLEAN               bFalse = FALSE;
    
    DEBUGP(DL_TRACE, ("===>SendNetBufferList: NBL = %p.\n", NetBufferLists));

    do
    {

       DispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags);
#if DBG
        //
        // we should never get packets to send if we are not in running state
        //
        
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
        //
        // If the filter is not in running state, fail the send
        // 
        if (pFilter->State != FilterRunning)
        {
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
            
            CurrNbl = NetBufferLists;
            while (CurrNbl)
            {
                NET_BUFFER_LIST_STATUS(CurrNbl) = NDIS_STATUS_PAUSED;
                CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
            }
            NdisFSendNetBufferListsComplete(pFilter->FilterHandle, 
                        NetBufferLists, 
                        DispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
            break;
            
        }
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif
        if (pFilter->TrackSends)
        {
            FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
            CurrNbl = NetBufferLists;
            while (CurrNbl)
            {
                pFilter->OutstandingSends++;
                FILTER_LOG_SEND_REF(1, pFilter, CurrNbl, pFilter->OutstandingSends);
                
                CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
            }
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
        }
        //
        // If necessary, queue the NetBufferList in a local structure for later processing
        //
        NdisFSendNetBufferLists(pFilter->FilterHandle, NetBufferLists, PortNumber, SendFlags);
        
        
    }
    while (bFalse);
    
    DEBUGP(DL_TRACE, ("<===SendNetBufferList. \n"));
}




VOID
FilterReturnNetBufferLists(
        IN  NDIS_HANDLE         FilterModuleContext,
        IN  PNET_BUFFER_LIST    NetBufferLists,
        IN  ULONG               ReturnFlags
        )
/*++

Routine Description:

    FilerReturnNetBufferLists handler
    FilterReturnNetBufferLists is an optional function. If provided NDIS calls 
    FitlerReturnNetBufferLists to return the ownership of one or more NetBufferLists
    and their embedded NetBuffers to the filter driver. If this handler is NULL, NDIS
    will skip calling this fitler when returning NetBufferLists to the underlying 
    miniport and will call the next lower fitler in the stack with a non_NULL 
    FilterReturnNetBufferLists handler or the miniport driver. A filter that doesn't
    provide a FitlerReturnNetBufferLists handler cannot initiate a receive indication
    on its own.

Arguments:

    FitlerInstanceContext: Pointer to our filter context area.
    NetBufferLists: A linked list of NetBufferLists that filter driver indicated by a 
                    previous call to NdisFIndicateReceiveNetBufferLists.
    ReturnFlags: Flags specifying if the caller is at DISPATCH_LEVEL
   

Return Value:

     NONE

--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    PNET_BUFFER_LIST    CurrNbl = NULL;
    UINT                NumOfNetBufferLists = 0;
    BOOLEAN             DispatchLevel;
    ULONG               Ref;
    
    DEBUGP(DL_TRACE, ("===>ReturnNetBufferLists, NetBufferLists is %p.\n", NetBufferLists));

    if (pFilter->TrackReceives)
    {
        while (CurrNbl)
        {
            //
            // Undo the operations it did with the NetBufferList on the receive indication
            //
            NumOfNetBufferLists ++;
            CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
        }
    }
    NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);
 
    if (pFilter->TrackReceives)
    {
        DispatchLevel = NDIS_TEST_RETURN_AT_DISPATCH_LEVEL(ReturnFlags);
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);

        pFilter->OutstandingRcvs -= NumOfNetBufferLists;
        Ref = pFilter->OutstandingRcvs;
        FILTER_LOG_RCV_REF(3, pFilter, NetBufferLists, Ref);
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
    }                


    DEBUGP(DL_TRACE, ("<===ReturnNetBufferLists.\n"));
    

}

/*
 * 参考WDK文档以及WDK例子代码，一个NBL对应一个Packet，通过NdisGetNextMdl即可遍历
 */
static int CopyFromNetBuffer(PUCHAR pDst, ULONG Size, PNET_BUFFER NetBuffer)
{
        PMDL pMdl = NULL;
        PUCHAR pSrc;
        ULONG BytesRemaining = Size;
        ULONG BytesToCopy = 0;
        ULONG TotalCpyBytes = 0;
        ULONG BytesAvailable;
        ULONG SrcTotalLenght = 0; // Source NetBuffer DataLenght
        ULONG Offset = 0;         // CurrentMdlOffset

        pMdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
        SrcTotalLenght = NET_BUFFER_DATA_LENGTH(NetBuffer);
        Offset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);

        while (BytesRemaining && (pMdl != NULL) && SrcTotalLenght) {
                NdisQueryMdl(pMdl, &pSrc, &BytesAvailable, NormalPagePriority);

                if (pSrc == NULL || BytesAvailable <= Offset) {
                        KdPrint(("ERROR:CopyFromNetBuffer mdl failed %x %d %d!\n",pSrc, BytesAvailable, Offset));
                        return -1;
                }

                BytesToCopy = (BytesAvailable - Offset > BytesRemaining) ?
                                BytesRemaining : BytesAvailable - Offset;

                BytesToCopy = (BytesToCopy > SrcTotalLenght) ? SrcTotalLenght : BytesToCopy;

                memcpy(pDst, pSrc + Offset, BytesToCopy);
                BytesRemaining -= BytesToCopy;
                pDst += BytesToCopy;

                SrcTotalLenght -= BytesToCopy;
                TotalCpyBytes += BytesToCopy;

                //    
                // CurrentMdlOffset is used only for the first Mdl processed. For the remaining Mdls, it is 0.
                //
                Offset = 0; 

                NdisGetNextMdl(pMdl, &pMdl);
        }

        /* SrcTotalLenght此时应该累减至0 */
        if (SrcTotalLenght > 0) {
                KdPrint(("WARN:CopyFromNetBuffer partial success %d %d!\n", 
                                        BytesToCopy, SrcTotalLenght));
        }

        return TotalCpyBytes;
}

VOID
InsertNblToRcvQueue(PMS_FILTER pFilter, PNET_BUFFER_LIST NetBufferLists)
/*
 * 调用者必须持有pFilter->Lock
 */
{
        PNET_BUFFER_LIST        pNetBufList;
        PNET_BUFFER             NetBuffer;
        
        for (pNetBufList = NetBufferLists; pNetBufList;) {
                for (NetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufList); 
                                NetBuffer;
                                NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer)){
                        PFILTER_NB_PACKET Packet = NULL;
                        ULONG NbLength = NET_BUFFER_DATA_LENGTH(NetBuffer);

                        Packet = (PFILTER_NB_PACKET)FILTER_ALLOC_MEM(pFilter->FilterHandle, 
                                        NbLength + sizeof(FILTER_NB_PACKET));
                        if (Packet == NULL){
                                DEBUGP(DL_ERROR, ("InsertNblToRcvQueue FILTER_ALLOC_MEM Failed.\n"));
                                break;
                        }

                        NdisZeroMemory(Packet, NbLength + sizeof(FILTER_NB_PACKET));

                        Packet->Buffer = Packet + 1;
                        Packet->Len =  CopyFromNetBuffer(Packet->Buffer, NbLength, NetBuffer);

                        InsertTailList(&pFilter->RcvNBLQueue, &Packet->Link);

                }
                pNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);
        }
}

VOID
FilterReceiveNetBufferLists(
        IN  NDIS_HANDLE         FilterModuleContext,
        IN  PNET_BUFFER_LIST    NetBufferLists,
        IN  NDIS_PORT_NUMBER    PortNumber,
        IN  ULONG               NumberOfNetBufferLists,
        IN  ULONG               ReceiveFlags
         )
/*++

Routine Description:

    FilerReceiveNetBufferLists is an optional function for filter drivers. 
    If provided, this function process receive indications made by underlying 
    NIC or lower level filter drivers. This function  can also be called as a 
    result of loopback. If this handler is NULL, NDIS will skip calling this
    filter when processing a receive indication and will call the next upper 
    filter in the stack with a non-NULL FitlerReceiveNetBufferLists handler 
    or the procotol driver. A filter that doesn't provide a 
    FilterReceiveNetBufferLists handler can not provided a 
    FilterReturnNetBufferLists handler or a initiate a receive indication on 
    its own.

Arguments:

    FilterModuleContext: Pointer to our filter context area.
    NetBufferLists: A linked list of NetBufferLists allocated by underlying driver each containing
                    one NetBuffer.
    PortNumber: Port on which the Receive is indicated
    ReceiveFlags: Flags associated with the Receive such as whether the filter
                  can pend the receive
   

Return Value:

    None
 
--*/
{

    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    BOOLEAN             DispatchLevel;
    ULONG               Ref;
    BOOLEAN               bFalse = FALSE;
#if DBG
    ULONG               ReturnFlags;
#endif
    
    DEBUGP(DL_TRACE, ("===>ReceiveNetBufferList: NetBufferLists = %p.\n", NetBufferLists));
    do
    {

        DispatchLevel = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);
#if DBG
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
 
        if (pFilter->State != FilterRunning)
        {
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

            if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
            {   
                ReturnFlags = 0;
                if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
                {
                    NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
                }
                
                NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);
            }
            break;
        }
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif

        ASSERT(NumberOfNetBufferLists >= 1);
            
        // 
        // If necessary, queue the NetBufferList in a local structure for later processing.
        // We may need to travel the list, some of them may not need post processing
        //
        if (pFilter->TrackReceives)
        {
            FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
            pFilter->OutstandingRcvs += NumberOfNetBufferLists;
            Ref = pFilter->OutstandingRcvs;

            //
            // We only capture packets in DOT11_OPERATION_MODE_NETWORK_MONITOR mode
            //
            if (DOT11_OPERATION_MODE_NETWORK_MONITOR == pFilter->Mode){
                    InsertNblToRcvQueue(pFilter, NetBufferLists);
            }
                                
            FILTER_LOG_RCV_REF(1, pFilter, NetBufferLists, Ref);
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
        }

        NdisFIndicateReceiveNetBufferLists(
                   pFilter->FilterHandle,
                   NetBufferLists,
                   PortNumber, 
                   NumberOfNetBufferLists,
                   ReceiveFlags);


        if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags) && 
            pFilter->TrackReceives)
        {
            FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
            pFilter->OutstandingRcvs -= NumberOfNetBufferLists;
            Ref = pFilter->OutstandingRcvs;
            FILTER_LOG_RCV_REF(2, pFilter, NetBufferLists, Ref);
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
        }

    } while (bFalse);
    
    DEBUGP(DL_TRACE, ("<===ReceiveNetBufferList: Flags = %8x.\n", ReceiveFlags));
    
}



VOID
FilterCancelSendNetBufferLists(
    IN  NDIS_HANDLE             FilterModuleContext,
    IN  PVOID                   CancelId
    )
/*++

Routine Description:

    This function cancels any NET_BUFFER_LISTs pended in the filter and then
    calls the NdisFCancelSendNetBufferLists to propagate the CancelSend to the next filter 
    miniport

Arguments:

    
Return Value:

    None

*/
{
    PMS_FILTER  pFilter = (PMS_FILTER)FilterModuleContext;

    NdisFCancelSendNetBufferLists(pFilter->FilterHandle,CancelId);
}


 
NDIS_STATUS
FilterSetModuleOptions(
    IN  NDIS_HANDLE             FilterModuleContext
    )
/*++

Routine Description:

    This function set the optional handlers for on the filter
      
Arguments:

    NetBufferLists: Pointer to the NetBufferList to be freed.
    DispatchLevel: A Boolean specifying if the caller is at DISPATCH_LEVEL        
  
Return Value:

    None
 
 NOTE: NetBufferList has to be allocated by the fitler
 
--*/
{
    
   PMS_FILTER                               pFilter = (PMS_FILTER)FilterModuleContext;
   NDIS_FILTER_PARTIAL_CHARACTERISTICS      OptionalHandlers;
   NDIS_STATUS                              Status = NDIS_STATUS_SUCCESS;
   BOOLEAN               bFalse = FALSE;

   //
   // Demonstrate how to change send/receive handlers at runtime.
   //
   if (bFalse)
   {
       UINT      i;

      
       pFilter->CallsRestart++;

       i = pFilter->CallsRestart % 8;

       pFilter->TrackReceives = TRUE;
       pFilter->TrackSends = TRUE;

       NdisMoveMemory(&OptionalHandlers, &DefaultChars, sizeof(OptionalHandlers));
       OptionalHandlers.Header.Type = NDIS_OBJECT_TYPE_FILTER_PARTIAL_CHARACTERISTICS;
       OptionalHandlers.Header.Size = sizeof(OptionalHandlers);
       switch (i)
       {
           
            case 0: 
                OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
                pFilter->TrackReceives = FALSE;
                break;

            case 1:
                
                OptionalHandlers.ReturnNetBufferListsHandler = NULL;
                pFilter->TrackReceives = FALSE;
                break;

            case 2:
                OptionalHandlers.SendNetBufferListsHandler = NULL;
                pFilter->TrackSends = FALSE;
                break;

            case 3:
                OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
                pFilter->TrackSends = FALSE;
                break;

            case 4:
                OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
                OptionalHandlers.ReturnNetBufferListsHandler = NULL;
                break;

            case 5:
                OptionalHandlers.SendNetBufferListsHandler = NULL;
                OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
                break;

            case 6:
                
                OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
                OptionalHandlers.ReturnNetBufferListsHandler = NULL;
                OptionalHandlers.SendNetBufferListsHandler = NULL;
                OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
                break;
                
            case 7:
                break;
       }
       Status = NdisSetOptionalHandlers(pFilter->FilterHandle, (PNDIS_DRIVER_OPTIONAL_HANDLERS)&OptionalHandlers );
   }
   return Status;
}



NDIS_STATUS
filterDoInternalRequest(
    IN PMS_FILTER                   FilterModuleContext,
    IN NDIS_REQUEST_TYPE            RequestType,
    IN NDIS_OID                     Oid,
    IN PVOID                        InformationBuffer,
    IN ULONG                        InformationBufferLength,
    IN ULONG                        OutputBufferLength, OPTIONAL
    IN ULONG                        MethodId, OPTIONAL
    OUT PULONG                      pBytesProcessed
    )
/*++

Routine Description:

    Utility routine that forms and sends an NDIS_OID_REQUEST to the
    miniport, waits for it to complete, and returns status
    to the caller.

    NOTE: this assumes that the calling routine ensures validity
    of the filter handle until this returns.

Arguments:

    FilterModuleContext - pointer to our filter module context
    RequestType - NdisRequest[Set|Query|method]Information
    Oid - the object being set/queried
    InformationBuffer - data for the request
    InformationBufferLength - length of the above
    OutputBufferLength  - valid only for method request
    MethodId - valid only for method request
    pBytesProcessed - place to return bytes read/written

Return Value:

    Status of the set/query request

--*/
{
    FILTER_REQUEST              FilterRequest;
    PNDIS_OID_REQUEST           NdisRequest = &FilterRequest.Request;
    NDIS_STATUS                 Status;
    BOOLEAN               bFalse;


    bFalse = FALSE;
    NdisZeroMemory(NdisRequest, sizeof(NDIS_OID_REQUEST));

    NdisInitializeEvent(&FilterRequest.ReqEvent);
    
    NdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    NdisRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
    NdisRequest->RequestType = RequestType;

    switch (RequestType)
    {
        case NdisRequestQueryInformation:
             NdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
             NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        case NdisRequestSetInformation:
             NdisRequest->DATA.SET_INFORMATION.Oid = Oid;
             NdisRequest->DATA.SET_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             NdisRequest->DATA.SET_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        case NdisRequestMethod:
             NdisRequest->DATA.METHOD_INFORMATION.Oid = Oid;
             NdisRequest->DATA.METHOD_INFORMATION.MethodId = MethodId;
             NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength =
                                    InformationBufferLength;
             NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength = OutputBufferLength;
             break;
             
                

        default:
            FILTER_ASSERT(bFalse);
            break;
    }

    NdisRequest->RequestId = (PVOID)FILTER_REQUEST_ID;
    
    Status = NdisFOidRequest(FilterModuleContext->FilterHandle,
                            NdisRequest);
    

    if (Status == NDIS_STATUS_PENDING)
    {
        
        NdisWaitEvent(&FilterRequest.ReqEvent, 0);
        Status = FilterRequest.Status;
    }


    if (Status == NDIS_STATUS_SUCCESS)
    {
        if (RequestType == NdisRequestSetInformation)
        {
            *pBytesProcessed = NdisRequest->DATA.SET_INFORMATION.BytesRead;
        }

        if (RequestType == NdisRequestQueryInformation)
        {
            *pBytesProcessed = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
        }

        if (RequestType == NdisRequestMethod)
        {
            *pBytesProcessed = NdisRequest->DATA.METHOD_INFORMATION.BytesWritten;
        }
        
        //
        // The driver below should set the correct value to BytesWritten 
        // or BytesRead. But now, we just truncate the value to InformationBufferLength
        //
        if (RequestType == NdisRequestMethod)
        {
            if (*pBytesProcessed > OutputBufferLength)
            {
                *pBytesProcessed = OutputBufferLength;
            }
        }
        else
        {
            
            if (*pBytesProcessed > InformationBufferLength)
            {
                *pBytesProcessed = InformationBufferLength;
            }
        }
    }


    return (Status);
}

VOID
filterInternalRequestComplete(
    IN NDIS_HANDLE                  FilterModuleContext,
    IN PNDIS_OID_REQUEST            NdisRequest,
    IN NDIS_STATUS                  Status
    )
/*++

Routine Description:

    NDIS entry point indicating completion of a pended NDIS_OID_REQUEST.

Arguments:

    FilterModuleContext - pointer to filter module context
    NdisRequest - pointer to NDIS request
    Status - status of request completion

Return Value:

    None

--*/
{
    PFILTER_REQUEST              FilterRequest;


    UNREFERENCED_PARAMETER(FilterModuleContext);
 
    //
    //  Get at the request context.
    //
    FilterRequest = CONTAINING_RECORD(NdisRequest, FILTER_REQUEST, Request);

    //
    //  Save away the completion status.
    //
    FilterRequest->Status = Status;

    //
    //  Wake up the thread blocked for this request to complete.
    //
    NdisSetEvent(&FilterRequest->ReqEvent);
}

