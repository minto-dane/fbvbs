with FBVBS.ABI;

package FBVBS.Hypercall_Dispatcher
  with SPARK_Mode
is
   procedure Dispatch
     (Tracker          : in out FBVBS.ABI.Command_Tracker_Record;
      Command_State    : in out FBVBS.ABI.Command_State;
      Caller           : in out FBVBS.ABI.Partition_Descriptor;
      Target_Partition : in out FBVBS.ABI.Partition_Descriptor;
      Host_Profile     : FBVBS.ABI.Host_Callsite_Profile_Record;
      Caps             : FBVBS.ABI.Platform_Capabilities;
      Domain           : FBVBS.ABI.IOMMU_Domain_Record;
      Artifact         : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Log_State        : in out FBVBS.ABI.Log_State_Record;
      Verify_State     : in out FBVBS.ABI.Verification_Record;
      Manifest_State   : in out FBVBS.ABI.Manifest_Set_Record;
      VCPU             : in out FBVBS.ABI.VCPU_Record;
      Memory_Object    : in out FBVBS.ABI.Memory_Object_Record;
      Next_Object_Id   : in out FBVBS.ABI.Handle;
      Next_Partition_Id : in out FBVBS.ABI.Handle;
      Target_Set_State : in out FBVBS.ABI.Target_Set_Record;
      Key_State        : in out FBVBS.ABI.Key_Record;
      Dek_State        : in out FBVBS.ABI.Dek_Record;
      Next_Target_Set_Id : in out FBVBS.ABI.Handle;
      Next_Key_Handle    : in out FBVBS.ABI.Handle;
      Next_Dek_Handle    : in out FBVBS.ABI.Handle;
      Request          : FBVBS.ABI.Dispatch_Request_Record;
      Result           : out FBVBS.ABI.Dispatch_Result_Record);
end FBVBS.Hypercall_Dispatcher;
