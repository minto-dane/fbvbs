with Interfaces;

package FBVBS.ABI
  with SPARK_Mode
is
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   subtype U8 is Interfaces.Unsigned_8;
   subtype U64 is Interfaces.Unsigned_64;
   subtype U32 is Interfaces.Unsigned_32;

   type Hash_Buffer is array (Natural range 0 .. 63) of U8;

   subtype KSI_Object_Slot is Natural range 0 .. 7;

    type Status_Code is
      (OK,
        Invalid_Parameter,
        Invalid_Caller,
         Permission_Denied,
          Invalid_State,
          Measurement_Failed,
         Signature_Invalid,
         Rollback_Detected,
         Revoked,
         Not_Supported_On_Platform,
         Not_Found,
         Already_Exists,
         Buffer_Too_Small,
         Resource_Exhausted,
        Policy_Denied,
        Resource_Busy,
        Generation_Mismatch,
        Dependency_Unsatisfied,
        Snapshot_Inconsistent,
        Freshness_Failed,
        Callsite_Rejected,
        Replay_Detected,
        Internal_Corruption);

   subtype Handle is U64;
   subtype Target_Count_Type is U32 range 0 .. 2;

   KCI_Expected_Generation : constant U64 := 1;
   Page_Size               : constant U64 := 4096;
   IKS_Op_Sign             : constant U32 := 16#1#;
   IKS_Op_Key_Exchange     : constant U32 := 16#2#;
   IKS_Op_Derive           : constant U32 := 16#4#;
   KCI_MSR_EFER            : constant U32 := 16#C000_0080#;
   KCI_MSR_LSTAR           : constant U32 := 16#C000_0082#;
   KCI_MSR_SFMASK          : constant U32 := 16#C000_0084#;
   Host_Callsite_FBVBS_Primary   : constant U64 := 16#FFFF_8000_0000_1000#;
   Host_Callsite_FBVBS_Secondary : constant U64 := 16#FFFF_8000_0000_1100#;
   Host_Callsite_VMM_Primary     : constant U64 := 16#FFFF_8000_0000_2000#;
   Host_Callsite_VMM_Secondary   : constant U64 := 16#FFFF_8000_0000_2100#;
   Mirror_Log_Ring_GPA           : constant U64 := 16#FFFF_8000_0001_0000#;
   Log_Record_Size              : constant U32 := 272;
   Log_Ring_Header_Size         : constant U32 := 40;
   Log_Payload_Max              : constant U32 := 220;
   Log_Slot_Count               : constant U32 := 32;
   Log_Ring_Total_Size          : constant U32 :=
     Log_Ring_Header_Size + (Log_Record_Size * Log_Slot_Count);
   UVS_Failure_Signature         : constant U32 := 16#01#;
    UVS_Failure_Revocation        : constant U32 := 16#02#;
    UVS_Failure_Generation        : constant U32 := 16#04#;
    UVS_Failure_Rollback          : constant U32 := 16#08#;
    UVS_Failure_Dependency        : constant U32 := 16#10#;
    UVS_Failure_Snapshot          : constant U32 := 16#20#;
    UVS_Failure_Freshness         : constant U32 := 16#40#;
    KSI_Operation_Exec_Elevation  : constant U32 := 1;
    KSI_Operation_Setuid_Family   : constant U32 := 2;
    KSI_Operation_Setgid_Family   : constant U32 := 3;
    KSI_Valid_RUID                : constant U32 := 16#01#;
    KSI_Valid_EUID                : constant U32 := 16#02#;
    KSI_Valid_SUID                : constant U32 := 16#04#;
    KSI_Valid_RGID                : constant U32 := 16#08#;
   KSI_Valid_EGID                : constant U32 := 16#10#;
   KSI_Valid_SGID                : constant U32 := 16#20#;
   KSI_Class_UCRED               : constant U32 := 1;
   KSI_Class_Prison              : constant U32 := 2;
   KSI_Class_Securelevel         : constant U32 := 3;
   KSI_Class_MAC                 : constant U32 := 4;
   KSI_Class_Capsicum            : constant U32 := 5;
   KSI_Class_Firewall            : constant U32 := 6;
   KSI_Class_P_TextVP            : constant U32 := 7;
   Fault_Code_Partition_Internal   : constant U32 := 1;
   Fault_Code_VM_Exit_Unclassified : constant U32 := 3;
   Source_Component_Microhypervisor : constant U32 := 1;
   Memory_Object_Flag_Private      : constant U32 := 16#0000#;
   Memory_Object_Flag_Shareable    : constant U32 := 16#0001#;
   Memory_Object_Flag_Guest_Memory : constant U32 := 16#0002#;
   Memory_Permission_Read          : constant U32 := 16#0001#;
   Memory_Permission_Write         : constant U32 := 16#0002#;
   Memory_Permission_Execute       : constant U32 := 16#0004#;
   VM_Reg_RIP                     : constant U32 := 1;
   VM_Reg_RSP                     : constant U32 := 2;
   VM_Reg_RFLAGS                  : constant U32 := 3;
   VM_Reg_CR0                     : constant U32 := 4;
   VM_Reg_CR3                     : constant U32 := 5;
   VM_Reg_CR4                     : constant U32 := 6;
   Capability_Memory_Map           : constant U64 := 2#0000_0010#;
   Capability_Memory_Set_Permission : constant U64 := 2#0000_0100#;
   Synthetic_Exit_RIP_PIO      : constant U64 := 16#0000_0000_FFF0_0001#;
   Synthetic_Exit_RIP_MMIO     : constant U64 := 16#0000_0000_FFF0_0002#;
   Synthetic_Exit_RIP_Shutdown : constant U64 := 16#0000_0000_FFF0_0003#;
   Synthetic_Exit_RIP_Fault    : constant U64 := 16#0000_0000_FFF0_0004#;
   VM_Flag_Nested_Virt_Disabled : constant U32 := 16#0001#;
   Max_Assigned_Devices         : constant := 8;

   subtype Device_Slot is Natural range 0 .. Max_Assigned_Devices - 1;
   type Device_Id_Array is array (Device_Slot) of Handle;

   type Key_Type is
     (No_Key,
      Ed25519,
      X25519,
      ECDSA_P256,
      RSA3072,
      ECDH_P256);

   function Has_Op (Allowed_Ops : U32; Operation : U32) return Boolean is
     ((Allowed_Ops and Operation) /= 0);

   function Supports_Sign (Kind : Key_Type) return Boolean is
     (Kind = Ed25519 or else Kind = ECDSA_P256 or else Kind = RSA3072);

   function Supports_Key_Exchange (Kind : Key_Type) return Boolean is
     (Kind = X25519 or else Kind = ECDH_P256);

   function Valid_Key_Length (Kind : Key_Type; Length : U32) return Boolean is
     (case Kind is
         when No_Key =>
           False,
         when Ed25519 | X25519 =>
           Length = 32,
         when ECDSA_P256 | ECDH_P256 =>
           Length = 32 or else Length = 121,
         when RSA3072 =>
           Length >= 256);

   type Verification_Record is record
      Approved_Module_Object_Id : Handle := 0;
      Approved_Manifest_Object_Id : Handle := 0;
      Approved_Generation       : U64 := 0;
      Pinned_CR0_Mask           : U64 := 0;
      Pinned_CR4_Mask           : U64 := 0;
      Intercepted_MSR_Count     : U32 := 0;
   end record;

   type KSI_Object_Record is record
      Active                 : Boolean := False;
      Tier_B                 : Boolean := False;
      Pointer_Registered     : Boolean := False;
      Retired                : Boolean := False;
      Protection_Class       : U32 := 0;
      Object_Id              : Handle := 0;
      Guest_Physical_Address : U64 := 0;
      Size                   : U64 := 0;
      Target_Set_Id          : Handle := 0;
   end record;

   type KSI_Object_Array is array (KSI_Object_Slot) of KSI_Object_Record;

     type Target_Set_Record is record
        In_Use                 : Boolean := False;
        Target_Set_Id          : Handle := 0;
        Target_Count           : Target_Count_Type := 0;
       First_Target_Object_Id : Handle := 0;
       Second_Target_Object_Id : Handle := 0;
       First_Target_Registered : Boolean := False;
        Second_Target_Registered : Boolean := False;
        First_Target_Protection_Class : U32 := 0;
        Second_Target_Protection_Class : U32 := 0;
        Pointer_Object_Id      : Handle := 0;
        Active_Target_Object_Id : Handle := 0;
        Replacement_Object_Id  : Handle := 0;
        Objects                : KSI_Object_Array := (others => (others => <>));
        Next_KSI_Object_Id     : Handle := 16#20000#;
     end record;

   type KSI_Shadow_State_Record is record
      Update_In_Progress : Boolean := False;
      Shadow_Object_Id   : Handle := 0;
      Candidate_Object_Id : Handle := 0;
      Observed_RIP       : U64 := 0;
      Writers_Paused     : Boolean := False;
      Write_Window_Open  : Boolean := False;
   end record;

   type Key_Record is record
      In_Use      : Boolean := False;
      Key_Handle  : Handle := 0;
      Key_Kind    : Key_Type := No_Key;
      Allowed_Ops : U32 := 0;
      Key_Length  : U32 := 0;
   end record;

   type Dek_Record is record
      In_Use     : Boolean := False;
      Dek_Handle : Handle := 0;
      Volume_Id  : U64 := 0;
      Key_Length : U32 := 0;
   end record;

   type Manifest_Set_Record is record
      In_Use                   : Boolean := False;
      Verified_Manifest_Set_Id : Handle := 0;
      Verdict                  : U32 := 0;
      Manifest_Count           : U32 := 0;
      Failure_Bitmap           : U32 := 0;
      Approved_Artifact_Object_Id : Handle := 0;
      Approved_Manifest_Object_Id : Handle := 0;
      Revoked_Object_Id        : Handle := 0;
   end record;

   type VCPU_State is
     (VCPU_Created,
      VCPU_Runnable,
      VCPU_Running,
      VCPU_Blocked,
      VCPU_Faulted,
      VCPU_Destroyed);

   type VM_Exit_Reason is
     (No_Exit,
      Exit_PIO,
      Exit_MMIO,
      Exit_External_Interrupt,
      Exit_EPT_Violation,
      Exit_CR_Access,
      Exit_MSR_Access,
      Exit_Halt,
      Exit_Shutdown,
      Exit_Unclassified_Fault);

   type VCPU_Record is record
      State                    : VCPU_State := VCPU_Created;
      RIP                      : U64 := 0;
      RSP                      : U64 := 0;
      RFlags                   : U64 := 0;
      CR0                      : U64 := 0;
      CR3                      : U64 := 0;
      CR4                      : U64 := 0;
      Pending_Interrupt_Vector : U32 := 0;
      Interrupt_Pending        : Boolean := False;
   end record;

   type VMX_Leaf_Exit_Record is record
      Exit_Reason             : VM_Exit_Reason := No_Exit;
      CR_Number               : U32 := 0;
      MSR_Address             : U32 := 0;
      Port                    : U32 := 0;
      Access_Size             : U32 := 0;
      Is_Write                : Boolean := False;
      Value                   : U64 := 0;
      Guest_Physical_Address  : U64 := 0;
   end record;

   type VMX_Run_Result is record
      Exit_Reason            : VM_Exit_Reason := No_Exit;
      Fault_Code             : U32 := 0;
      Detail0                : U64 := 0;
      Detail1                : U64 := 0;
      Interrupt_Vector       : U32 := 0;
      CR_Number              : U32 := 0;
      MSR_Address            : U32 := 0;
      Port                   : U32 := 0;
      Access_Size            : U32 := 0;
      Is_Write               : Boolean := False;
      Value                  : U64 := 0;
      Guest_Physical_Address : U64 := 0;
   end record;

   type Platform_Capabilities is record
      Has_HLAT  : Boolean := False;
      Has_IOMMU : Boolean := False;
   end record;

   type IOMMU_Domain_Record is record
      In_Use                : Boolean := False;
      Domain_Id             : Handle := 0;
      Owner_Partition_Id    : Handle := 0;
      Attached_Device_Count : U32 := 0;
   end record;

   type Command_State is
     (Command_Empty,
      Command_Ready,
      Command_Executing,
      Command_Completed,
      Command_Failed);

   type Command_Tracker_Record is record
      Sequence_Seen : Boolean := False;
      Last_Sequence : U64 := 0;
      Last_Nonce    : U64 := 0;
   end record;

   Call_Partition_Create       : constant U32 := 16#0001#;
   Call_Partition_Destroy      : constant U32 := 16#0002#;
   Call_Partition_Get_Status   : constant U32 := 16#0003#;
   Call_Partition_Quiesce      : constant U32 := 16#0004#;
   Call_Partition_Resume       : constant U32 := 16#0005#;
   Call_Partition_Measure      : constant U32 := 16#0006#;
   Call_Partition_Load_Image   : constant U32 := 16#0007#;
   Call_Partition_Start        : constant U32 := 16#0008#;
   Call_Partition_Recover      : constant U32 := 16#0009#;
   Call_Partition_Get_Fault_Info : constant U32 := 16#000A#;
   Call_Memory_Allocate_Object : constant U32 := 16#1000#;
   Call_Memory_Map             : constant U32 := 16#1001#;
   Call_Memory_Unmap           : constant U32 := 16#1002#;
   Call_Memory_Set_Permission  : constant U32 := 16#1003#;
   Call_Memory_Register_Shared : constant U32 := 16#1004#;
   Call_Memory_Release_Object  : constant U32 := 16#1005#;
   Call_Memory_Unregister_Shared : constant U32 := 16#1006#;
   Call_KSI_Create_Target_Set  : constant U32 := 16#3000#;
   Call_KSI_Register_Tier_A    : constant U32 := 16#3001#;
   Call_KSI_Register_Tier_B    : constant U32 := 16#3002#;
   Call_KSI_Modify_Tier_B      : constant U32 := 16#3003#;
   Call_KSI_Register_Pointer   : constant U32 := 16#3004#;
   Call_KSI_Validate_Setuid    : constant U32 := 16#3005#;
   Call_KSI_Allocate_Ucred     : constant U32 := 16#3006#;
   Call_KSI_Replace_Tier_B_Object : constant U32 := 16#3007#;
   Call_KSI_Unregister_Object  : constant U32 := 16#3008#;
   Call_IKS_Import_Key         : constant U32 := 16#4001#;
   Call_IKS_Sign               : constant U32 := 16#4002#;
   Call_IKS_Key_Exchange       : constant U32 := 16#4003#;
   Call_IKS_Derive             : constant U32 := 16#4004#;
   Call_IKS_Destroy_Key        : constant U32 := 16#4005#;
   Call_SKS_Import_DEK         : constant U32 := 16#5001#;
   Call_SKS_Decrypt_Batch      : constant U32 := 16#5002#;
   Call_SKS_Encrypt_Batch      : constant U32 := 16#5003#;
   Call_SKS_Destroy_DEK        : constant U32 := 16#5004#;
   Call_KCI_Verify_Module      : constant U32 := 16#2001#;
   Call_KCI_Set_WX             : constant U32 := 16#2002#;
   Call_KCI_Pin_CR             : constant U32 := 16#2003#;
   Call_KCI_Intercept_MSR      : constant U32 := 16#2004#;
   Call_UVS_Verify_Manifest_Set : constant U32 := 16#6001#;
   Call_UVS_Verify_Artifact    : constant U32 := 16#6002#;
   Call_UVS_Check_Revocation   : constant U32 := 16#6003#;
   Call_VM_Create              : constant U32 := 16#7001#;
   Call_VM_Destroy             : constant U32 := 16#7002#;
   Call_VM_Run                 : constant U32 := 16#7003#;
   Call_VM_Set_Register        : constant U32 := 16#7004#;
   Call_VM_Get_Register        : constant U32 := 16#7005#;
   Call_VM_Map_Memory          : constant U32 := 16#7006#;
   Call_VM_Inject_Interrupt    : constant U32 := 16#7007#;
   Call_VM_Assign_Device       : constant U32 := 16#7008#;
   Call_VM_Release_Device      : constant U32 := 16#7009#;
   Call_VM_Get_VCPU_Status     : constant U32 := 16#700A#;
   Call_Audit_Get_Mirror_Info  : constant U32 := 16#8001#;
   Call_Audit_Get_Boot_Id      : constant U32 := 16#8002#;
   Call_Diag_Get_Partition_List : constant U32 := 16#8003#;
   Call_Diag_Get_Capabilities  : constant U32 := 16#8004#;
   Call_Diag_Get_Artifact_List : constant U32 := 16#8005#;
   Call_Diag_Get_Device_List   : constant U32 := 16#8006#;
   Cap_Bitmap0_MBEC_Or_GMET    : constant U64 := 2#0001#;
   Cap_Bitmap0_HLAT            : constant U64 := 2#0010#;
   Cap_Bitmap0_CET             : constant U64 := 2#0100#;
   Cap_Bitmap0_AESNI           : constant U64 := 2#1000#;
   Cap_Bitmap1_IOMMU           : constant U64 := 2#0001#;

   type Partition_State is
     (Created,
      Measured,
      Loaded,
      Runnable,
      Running,
      Quiesced,
      Faulted,
      Destroyed);

   type Trusted_Service_Kind is
     (Service_None,
      Service_KCI,
      Service_KSI,
      Service_IKS,
      Service_SKS,
      Service_UVS);

   type Partition_Kind is
     (Partition_None,
      Partition_FreeBSD_Host,
      Partition_Trusted_Service,
      Partition_Guest_VM);

   type Host_Caller_Class is
     (Host_Caller_None,
      Host_Caller_FBVBS,
      Host_Caller_VMM);

   type Artifact_Object_Kind is
     (Artifact_None,
      Artifact_Image,
      Artifact_Manifest,
      Artifact_Module);

   type Manifest_Component_Type is
     (Manifest_Component_None,
      Manifest_Trusted_Service,
      Manifest_Guest_Boot,
      Manifest_FreeBSD_Kernel,
      Manifest_FreeBSD_Module);

   type Artifact_Catalog_Entry_Record is record
      Object_Id      : Handle := 0;
      Object_Kind    : Artifact_Object_Kind := Artifact_None;
      Related_Index  : U32 := 0;
   end record;

   type Manifest_Profile_Record is record
      Component_Type      : Manifest_Component_Type := Manifest_Component_None;
      Object_Id          : Handle := 0;
      Manifest_Object_Id : Handle := 0;
      Service_Kind       : Trusted_Service_Kind := Service_None;
      VCPU_Count         : U32 := 0;
      Memory_Limit_Bytes : U64 := 0;
      Capability_Mask    : U64 := 0;
      Entry_IP           : U64 := 0;
      Initial_SP         : U64 := 0;
   end record;

   type Host_Callsite_Profile_Record is record
      Object_Id          : Handle := 0;
      Manifest_Object_Id : Handle := 0;
      Caller_Class       : Host_Caller_Class := Host_Caller_None;
      Load_Base          : U64 := 0;
      Primary_Offset     : U64 := 0;
      Secondary_Offset   : U64 := 0;
   end record;

   function Primary_Callsite (Profile : Host_Callsite_Profile_Record) return U64 is
     (Profile.Load_Base + Profile.Primary_Offset);

   function Secondary_Callsite (Profile : Host_Callsite_Profile_Record) return U64 is
     (Profile.Load_Base + Profile.Secondary_Offset);

   type Log_State_Record is record
      Initialized           : Boolean := False;
      Write_Offset          : U32 := 0;
      Max_Readable_Sequence : U64 := 0;
      Boot_Id_Hi            : U64 := 0;
      Boot_Id_Lo            : U64 := 0;
   end record;

   type Partition_Descriptor is record
        In_Use            : Boolean := False;
       Partition_Id      : U64     := 0;
       Kind              : Partition_Kind := Partition_None;
       State             : Partition_State := Created;
       Measurement_Epoch : U64     := 0;
       Service_Kind      : Trusted_Service_Kind := Service_None;
        Memory_Limit_Bytes : U64 := 0;
        Capability_Mask    : U64 := 0;
        Mapped_Bytes       : U64 := 0;
        Last_Fault_Code    : U32 := 0;
        Last_Source_Component : U32 := 0;
        Last_Fault_Detail0 : U64 := 0;
        Last_Fault_Detail1 : U64 := 0;
        VM_Flags              : U32 := 0;
        Assigned_Device_Count : U32 := 0;
        Assigned_Devices      : Device_Id_Array := (others => 0);
     end record;

   type Memory_Object_Record is record
      Allocated        : Boolean := False;
      Object_Flags     : U32 := 0;
      Memory_Object_Id : Handle := 0;
      Size             : U64 := 0;
      Map_Count        : U32 := 0;
      Shared_Count     : U32 := 0;
   end record;

   type Dispatch_Request_Record is record
      Call_Id                  : U32 := 0;
      Caller_Sequence          : U64 := 0;
      Caller_Nonce             : U64 := 0;
      Observed_RIP             : U64 := 0;
      Actual_Output_Length     : U32 := 0;
      Verified_Manifest_Set_Id : Handle := 0;
      Manifest_Count           : U32 := 0;
      Revoked_Object_Id        : Handle := 0;
      Signatures_Valid         : Boolean := False;
      Not_Revoked              : Boolean := False;
      Generation_Valid         : Boolean := False;
      Rollback_Free            : Boolean := False;
      Dependencies_Satisfied   : Boolean := False;
      Snapshot_Consistent      : Boolean := False;
      Freshness_Valid          : Boolean := False;
      Artifact_Object_Id       : Handle := 0;
      Manifest_Object_Id       : Handle := 0;
      Tail_Zero                : Boolean := False;
      Hash_Matches             : Boolean := False;
      Approval_Present         : Boolean := False;
      Has_Image                : Boolean := False;
      Module_Object_Id         : Handle := 0;
      Generation               : U64 := 0;
      Requested_Kind           : Partition_Kind := Partition_None;
      Requested_VCPU_Count     : U32 := 0;
      Requested_Memory_Limit   : U64 := 0;
      Requested_Capability_Mask : U64 := 0;
      Image_Object_Id          : Handle := 0;
      Create_Flags             : U32 := 0;
      Target_Count             : Target_Count_Type := 0;
      Target_Set_Id            : Handle := 0;
      First_Target_Object_Id   : Handle := 0;
      Second_Target_Object_Id  : Handle := 0;
      Pointer_Object_Id        : Handle := 0;
      Key_Handle               : Handle := 0;
      Dek_Handle               : Handle := 0;
      Volume_Id                : U64 := 0;
      VCPU_Id                  : U32 := 0;
      Interrupt_Vector         : U32 := 0;
      Has_HLAT                 : Boolean := False;
      Mapped_Bytes             : U64 := 0;
      Object_Id                : Handle := 0;
      Memory_Object_Id         : Handle := 0;
       Size                     : U64 := 0;
       File_Offset              : U64 := 0;
       Guest_Physical_Address   : U64 := 0;
       Protection_Class         : U32 := 0;
       Object_Flags             : U32 := 0;
       Key_Length               : U32 := 0;
       Allowed_Ops              : U32 := 0;
      Requested_Key_Kind       : Key_Type := No_Key;
      Permissions              : U32 := 0;
      Peer_Partition_Id        : Handle := 0;
       Descriptor_Count         : U32 := 0;
       Page_Aligned             : Boolean := False;
       Patch_Length             : U32 := 0;
       FSID                     : U64 := 0;
       File_Id                  : U64 := 0;
       Measured_Hash            : Hash_Buffer := (others => 0);
       Operation_Class          : U32 := 0;
       Valid_Mask               : U32 := 0;
       Requested_RUID           : U32 := 0;
       Requested_EUID           : U32 := 0;
       Requested_SUID           : U32 := 0;
       Requested_RGID           : U32 := 0;
       Requested_EGID           : U32 := 0;
       Requested_SGID           : U32 := 0;
       Requested_UID            : U32 := 0;
       Requested_GID            : U32 := 0;
       Caller_Ucred_Object_Id   : Handle := 0;
       Jail_Context_Id          : Handle := 0;
       MAC_Context_Id           : Handle := 0;
       Prison_Object_Id         : Handle := 0;
       Template_Ucred_Object_Id : Handle := 0;
       Has_File                 : Boolean := False;
       Hash_Present             : Boolean := False;
       Jail_Context_OK          : Boolean := False;
      MAC_Context_OK           : Boolean := False;
      New_Object_Id            : Handle := 0;
      VM_Flags                 : U32 := 0;
      Register_Id              : U32 := 0;
      Register_Value           : U64 := 0;
      Pin_Register             : U32 := 0;
      Pin_Mask                 : U64 := 0;
      MSR_Address              : U32 := 0;
      Enable                   : Boolean := False;
      Known_Object             : Boolean := False;
      Device_Id                : Handle := 0;
      Device_Segment           : U32 := 0;
      Device_Bus               : U32 := 0;
      Device_Slot_Function     : U32 := 0;
   end record;

   type Diag_Capabilities_Record is record
      Capability_Bitmap0 : U64 := 0;
      Capability_Bitmap1 : U64 := 0;
   end record;

   type Diag_Partition_Record is record
      Count        : U32 := 0;
      Partition_Id : Handle := 0;
      State        : Partition_State := Created;
      Kind         : Partition_Kind := Partition_None;
      Service_Kind : Trusted_Service_Kind := Service_None;
   end record;

   type Diag_Artifact_Record is record
      Count         : U32 := 0;
      Object_Id     : Handle := 0;
      Object_Kind   : Artifact_Object_Kind := Artifact_None;
      Related_Index : U32 := 0;
   end record;

   type Diag_Device_Record is record
      Count         : U32 := 0;
      Device_Id     : Handle := 0;
      Segment       : U32 := 0;
      Bus           : U32 := 0;
      Slot_Function : U32 := 0;
   end record;

   type Partition_Status_Record is record
      State             : Partition_State := Created;
      Measurement_Epoch : U64 := 0;
   end record;

   type Audit_Mirror_Info_Record is record
      Ring_GPA    : U64 := 0;
      Ring_Size   : U32 := 0;
      Record_Size : U32 := 0;
   end record;

   type Fault_Info_Record is record
      Fault_Code       : U32 := 0;
      Source_Component : U32 := 0;
      Fault_Detail0    : U64 := 0;
      Fault_Detail1    : U64 := 0;
   end record;

   type Dispatch_Result_Record is record
      Hypercall_Status     : Status_Code := OK;
      Actual_Output_Length : U32 := 0;
      Revoked              : Boolean := False;
      Failure_Bitmap       : U32 := 0;
      Partition_Id         : Handle := 0;
      Memory_Object_Id     : Handle := 0;
      Ucred_Object_Id      : Handle := 0;
      Shared_Object_Id     : Handle := 0;
      Target_Set_Id        : Handle := 0;
      Key_Handle           : Handle := 0;
      Dek_Handle           : Handle := 0;
      Register_Value       : U64 := 0;
      Verdict              : U32 := 0;
      Returned_Length      : U32 := 0;
      Completed_Count      : U32 := 0;
      Boot_Id_Hi           : U64 := 0;
      Boot_Id_Lo           : U64 := 0;
      Diag_Capabilities    : Diag_Capabilities_Record;
      Diag_Partition       : Diag_Partition_Record;
      Diag_Artifact        : Diag_Artifact_Record;
      Diag_Device          : Diag_Device_Record;
      Partition_Status     : Partition_Status_Record;
      Audit_Mirror         : Audit_Mirror_Info_Record;
      Fault_Info           : Fault_Info_Record;
      VCPU_State_Value     : VCPU_State := VCPU_Created;
      VM_Result            : VMX_Run_Result;
   end record;
end FBVBS.ABI;
