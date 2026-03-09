with FBVBS.ABI;
with FBVBS.Boot;
with FBVBS.Commands;
with FBVBS.Hypercall_Dispatcher;
with FBVBS.IKS;
with FBVBS.KCI;
with FBVBS.KSI;
with FBVBS.KSI_Shadow;
with FBVBS.Logging;
with FBVBS.Memory;
with FBVBS.Platform;
with FBVBS.Partitions;
with FBVBS.SKS;
with FBVBS.UVS;
with FBVBS.VM_Exit_Encoding;
with FBVBS.VMX;

procedure FBVBS_Hypervisor_Main is
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.Command_State;
   use type FBVBS.ABI.Host_Caller_Class;
   use type FBVBS.ABI.Partition_Kind;
    use type FBVBS.ABI.Partition_State;
    use type FBVBS.ABI.Trusted_Service_Kind;
    use type FBVBS.ABI.Handle;
    use type FBVBS.ABI.U32;
   use type FBVBS.ABI.VCPU_State;
   use type FBVBS.ABI.VM_Exit_Reason;

   Host_Partition : FBVBS.ABI.Partition_Descriptor;
   Partition      : FBVBS.ABI.Partition_Descriptor;
   Guest_VM       : FBVBS.ABI.Partition_Descriptor;
   Verify_State : FBVBS.ABI.Verification_Record;
    Target_Set   : FBVBS.ABI.Target_Set_Record;
    Shadow_State : FBVBS.ABI.KSI_Shadow_State_Record;
   Signing_Key  : FBVBS.ABI.Key_Record;
   Exchange_Key : FBVBS.ABI.Key_Record;
   Dek_State    : FBVBS.ABI.Dek_Record;
   Manifest_Set : FBVBS.ABI.Manifest_Set_Record;
   Caps         : FBVBS.ABI.Platform_Capabilities;
   IOMMU_Domain : FBVBS.ABI.IOMMU_Domain_Record;
    Command_Tracker : FBVBS.ABI.Command_Tracker_Record;
   Command_State   : FBVBS.ABI.Command_State := FBVBS.ABI.Command_Ready;
   VCPU         : FBVBS.ABI.VCPU_Record;
   Run_Result   : FBVBS.ABI.VMX_Run_Result;
    Next_Domain  : FBVBS.ABI.Handle := 16#700000#;
    Revoked      : Boolean := False;
    Status       : FBVBS.ABI.Status_Code;
   Log_State    : FBVBS.ABI.Log_State_Record;
   KCI_Profile  : constant FBVBS.ABI.Manifest_Profile_Record :=
     (Component_Type     => FBVBS.ABI.Manifest_Trusted_Service,
      Object_Id          => 16#1000#,
      Manifest_Object_Id => 16#2000#,
      Service_Kind       => FBVBS.ABI.Service_KCI,
      VCPU_Count         => 1,
      Memory_Limit_Bytes => 16#2000#,
      Capability_Mask    => 16#3F#,
      Entry_IP           => 16#400000#,
      Initial_SP         => 16#800000#);
   KSI_Profile  : constant FBVBS.ABI.Manifest_Profile_Record :=
     (Component_Type     => FBVBS.ABI.Manifest_Trusted_Service,
      Object_Id          => 16#1100#,
      Manifest_Object_Id => 16#2100#,
      Service_Kind       => FBVBS.ABI.Service_KSI,
      VCPU_Count         => 1,
      Memory_Limit_Bytes => 16#2000#,
      Capability_Mask    => 16#1#,
      Entry_IP           => 16#401000#,
      Initial_SP         => 16#801000#);
   Guest_Profile : constant FBVBS.ABI.Manifest_Profile_Record :=
     (Component_Type     => FBVBS.ABI.Manifest_Guest_Boot,
      Object_Id          => 16#1400#,
      Manifest_Object_Id => 16#2400#,
      Service_Kind       => FBVBS.ABI.Service_None,
      VCPU_Count         => 1,
      Memory_Limit_Bytes => 0,
      Capability_Mask    => 0,
      Entry_IP           => 16#500000#,
      Initial_SP         => 0);
   FBVBS_Host_Profile : constant FBVBS.ABI.Host_Callsite_Profile_Record :=
     (Object_Id          => 16#1700#,
      Manifest_Object_Id => 16#2700#,
      Caller_Class       => FBVBS.ABI.Host_Caller_FBVBS,
      Load_Base          => 16#FFFF_8000_0000_0000#,
      Primary_Offset     => 16#1000#,
      Secondary_Offset   => 16#1100#);
   Relocated_Host_Profile : constant FBVBS.ABI.Host_Callsite_Profile_Record :=
     (Object_Id          => 16#1700#,
      Manifest_Object_Id => 16#2700#,
      Caller_Class       => FBVBS.ABI.Host_Caller_FBVBS,
      Load_Base          => 16#FFFF_8000_0000_0000#,
      Primary_Offset     => 16#3000#,
      Secondary_Offset   => 16#3100#);
   KCI_Artifact : constant FBVBS.ABI.Artifact_Catalog_Entry_Record :=
     (Object_Id => 16#1000#, Object_Kind => FBVBS.ABI.Artifact_Image, Related_Index => 1);
   KCI_Manifest : constant FBVBS.ABI.Artifact_Catalog_Entry_Record :=
     (Object_Id => 16#2000#, Object_Kind => FBVBS.ABI.Artifact_Manifest, Related_Index => 0);
   Host_Kernel_Artifact : constant FBVBS.ABI.Artifact_Catalog_Entry_Record :=
     (Object_Id => 16#1700#, Object_Kind => FBVBS.ABI.Artifact_Image, Related_Index => 16);
   Host_Kernel_Manifest : constant FBVBS.ABI.Artifact_Catalog_Entry_Record :=
     (Object_Id => 16#2700#, Object_Kind => FBVBS.ABI.Artifact_Manifest, Related_Index => 15);
   VMM_Module_Artifact : constant FBVBS.ABI.Artifact_Catalog_Entry_Record :=
     (Object_Id => 16#3700#, Object_Kind => FBVBS.ABI.Artifact_Module, Related_Index => 18);
   VMM_Module_Manifest : constant FBVBS.ABI.Artifact_Catalog_Entry_Record :=
     (Object_Id => 16#2800#, Object_Kind => FBVBS.ABI.Artifact_Manifest, Related_Index => 17);
begin
    FBVBS.Partitions.Initialize (Host_Partition);
    FBVBS.Partitions.Bootstrap_FreeBSD_Host (Host_Partition, Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Boot.Validate_Catalog_Pair
      (Artifact_Entry => KCI_Artifact,
       Artifact_Index => 0,
       Manifest_Entry => KCI_Manifest,
       Manifest_Index => 1,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Boot.Validate_Profile_Binding
      (Profile        => KCI_Profile,
       Artifact_Entry => KCI_Artifact,
       Manifest_Entry => KCI_Manifest,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Boot.Validate_Catalog_Pair
      (Artifact_Entry => Host_Kernel_Artifact,
       Artifact_Index => 15,
       Manifest_Entry => Host_Kernel_Manifest,
       Manifest_Index => 16,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Boot.Validate_Catalog_Pair
      (Artifact_Entry => VMM_Module_Artifact,
       Artifact_Index => 17,
       Manifest_Entry => VMM_Module_Manifest,
       Manifest_Index => 18,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Boot.Validate_Host_Profile
      (Profile        => FBVBS_Host_Profile,
       Artifact_Entry => Host_Kernel_Artifact,
       Manifest_Entry => Host_Kernel_Manifest,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Logging.Initialize
      (State      => Log_State,
       Boot_Id_Hi => 16#1122_3344_5566_7788#,
       Boot_Id_Lo => 16#8877_6655_4433_2211#,
       Status     => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Logging.Append_Record
      (State          => Log_State,
       Payload_Length => FBVBS.ABI.Log_Payload_Max,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    pragma Assert (Log_State.Write_Offset = 0);
    for Index in 1 .. Integer (FBVBS.ABI.Log_Slot_Count) loop
       FBVBS.Logging.Append_Record
         (State          => Log_State,
          Payload_Length => 1,
          Status         => Status);
       pragma Assert (Status = FBVBS.ABI.OK);
    end loop;
    pragma Assert (Log_State.Max_Readable_Sequence = FBVBS.ABI.U64 (FBVBS.ABI.Log_Slot_Count) + 1);
    pragma Assert (Log_State.Write_Offset = 0);
    FBVBS.Logging.Append_Record
      (State          => Log_State,
       Payload_Length => FBVBS.ABI.Log_Payload_Max + 1,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Parameter);
    pragma Assert (Host_Partition.Kind = FBVBS.ABI.Partition_FreeBSD_Host);
    pragma Assert (Host_Partition.State = FBVBS.ABI.Runnable);
    FBVBS.Commands.Validate_Caller
      (Host_Partition,
       Require_Host          => True,
       Required_Service_Kind => FBVBS.ABI.Service_None,
       Status                => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Commands.Validate_Host_Callsite
      (Observed_RIP   => FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile),
       Primary_Callsite => FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile),
       Secondary_Callsite => FBVBS.ABI.Secondary_Callsite (FBVBS_Host_Profile),
       Required_Class => FBVBS.ABI.Host_Caller_FBVBS,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Commands.Validate_Host_Callsite
      (Observed_RIP   => FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile),
       Primary_Callsite => FBVBS.ABI.Host_Callsite_VMM_Primary,
       Secondary_Callsite => FBVBS.ABI.Host_Callsite_VMM_Secondary,
       Required_Class => FBVBS.ABI.Host_Caller_VMM,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.Callsite_Rejected);
    FBVBS.Commands.Validate_Host_Callsite
      (Observed_RIP   => FBVBS.ABI.Secondary_Callsite (Relocated_Host_Profile),
       Primary_Callsite => FBVBS.ABI.Primary_Callsite (Relocated_Host_Profile),
       Secondary_Callsite => FBVBS.ABI.Secondary_Callsite (Relocated_Host_Profile),
       Required_Class => FBVBS.ABI.Host_Caller_FBVBS,
       Status         => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Commands.Validate_Caller
      (Host_Partition,
       Require_Host          => False,
       Required_Service_Kind => FBVBS.ABI.Service_KCI,
       Status                => Status);
    pragma Assert (Status = FBVBS.ABI.OK);

    FBVBS.Partitions.Initialize (Partition);
    FBVBS.Partitions.Validate_Create_Profile
      (Requested_VCPU_Count   => KCI_Profile.VCPU_Count,
       Expected_VCPU_Count    => KCI_Profile.VCPU_Count,
       Requested_Memory_Limit => 16#2000#,
       Expected_Memory_Limit  => KCI_Profile.Memory_Limit_Bytes,
       Requested_Capability   => KCI_Profile.Capability_Mask,
       Expected_Capability    => KCI_Profile.Capability_Mask,
       Status                 => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Validate_Create_Profile
      (Requested_VCPU_Count   => 1,
       Expected_VCPU_Count    => 1,
       Requested_Memory_Limit => 16#4000#,
       Expected_Memory_Limit  => 16#2000#,
       Requested_Capability   => 16#1#,
       Expected_Capability    => 16#1#,
       Status                 => Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Parameter);
    FBVBS.Partitions.Validate_Load_Profile
      (Requested_Entry_IP   => KSI_Profile.Entry_IP,
       Expected_Entry_IP    => KSI_Profile.Entry_IP,
       Requested_Initial_SP => KSI_Profile.Initial_SP,
       Expected_Initial_SP  => KSI_Profile.Initial_SP,
       Require_Explicit_Stack => False,
       Status               => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Validate_Load_Profile
      (Requested_Entry_IP   => 0,
       Expected_Entry_IP    => KSI_Profile.Entry_IP,
       Requested_Initial_SP => 0,
       Expected_Initial_SP  => KSI_Profile.Initial_SP,
       Require_Explicit_Stack => False,
       Status               => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Validate_Load_Profile
      (Requested_Entry_IP   => KSI_Profile.Entry_IP,
       Expected_Entry_IP    => KSI_Profile.Entry_IP,
       Requested_Initial_SP => 16#900000#,
       Expected_Initial_SP  => KSI_Profile.Initial_SP,
       Require_Explicit_Stack => False,
       Status               => Status);
    pragma Assert (Status = FBVBS.ABI.Measurement_Failed);
    FBVBS.Partitions.Validate_Load_Profile
      (Requested_Entry_IP   => 0,
       Expected_Entry_IP    => Guest_Profile.Entry_IP,
       Requested_Initial_SP => 16#900000#,
       Expected_Initial_SP  => Guest_Profile.Initial_SP,
       Require_Explicit_Stack => True,
       Status               => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Validate_Load_Profile
      (Requested_Entry_IP   => 0,
       Expected_Entry_IP    => Guest_Profile.Entry_IP,
       Requested_Initial_SP => 0,
       Expected_Initial_SP  => Guest_Profile.Initial_SP,
       Require_Explicit_Stack => True,
       Status               => Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Parameter);
    FBVBS.Partitions.Create (Partition, 2, Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    pragma Assert (Partition.Kind = FBVBS.ABI.Partition_Trusted_Service);
    FBVBS.Commands.Validate_Caller
      (Partition,
       Require_Host          => True,
       Required_Service_Kind => FBVBS.ABI.Service_None,
       Status                => Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Caller);
    FBVBS.UVS.Initialize (Manifest_Set);
    FBVBS.UVS.Verify_Manifest_Set
      (Manifest_Set,
       Verified_Manifest_Set_Id => 16#5FFFFF#,
       Manifest_Count           => 5,
       Revoked_Object_Id        => 16#2000#,
       Signatures_Valid         => True,
       Not_Revoked              => True,
       Generation_Valid         => True,
       Rollback_Free            => True,
       Dependencies_Satisfied   => True,
       Snapshot_Consistent      => True,
       Freshness_Valid          => False,
       Status                   => Status);
    pragma Assert (Status = FBVBS.ABI.Freshness_Failed);
    pragma Assert (Manifest_Set.Failure_Bitmap = FBVBS.ABI.UVS_Failure_Freshness);
    pragma Assert (Manifest_Set.Verdict = 0);
    FBVBS.UVS.Initialize (Manifest_Set);
    FBVBS.UVS.Verify_Manifest_Set
      (Manifest_Set,
       Verified_Manifest_Set_Id => 16#600000#,
       Manifest_Count           => 5,
       Revoked_Object_Id        => 0,
       Signatures_Valid         => True,
       Not_Revoked              => True,
       Generation_Valid         => True,
       Rollback_Free            => True,
       Dependencies_Satisfied   => True,
       Snapshot_Consistent      => True,
       Freshness_Valid          => True,
       Status                   => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Measure (Partition, Approval_Present => False, Status => Status);
    pragma Assert (Status = FBVBS.ABI.Signature_Invalid);
    FBVBS.UVS.Verify_Artifact
      (Manifest_Set,
       Artifact_Object_Id => 16#1000#,
       Manifest_Object_Id => 16#2000#,
       Tail_Zero          => True,
       Hash_Matches       => True,
       Status             => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.UVS.Require_Artifact_Approval
      (Manifest_Set,
       Artifact_Object_Id => 16#1000#,
       Manifest_Object_Id => 16#2000#,
       Status             => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Measure (Partition, Approval_Present => True, Status => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Commands.Validate_Caller
      (Partition,
       Require_Host          => False,
       Required_Service_Kind => FBVBS.ABI.Service_KCI,
       Status                => Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Caller);
    FBVBS.Partitions.Bind_Service (Partition, FBVBS.ABI.Service_KCI, Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Commands.Validate_Caller
      (Partition,
       Require_Host          => False,
       Required_Service_Kind => FBVBS.ABI.Service_KCI,
       Status                => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.Partitions.Bind_Service (Partition, FBVBS.ABI.Service_KSI, Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Caller);

    FBVBS.Partitions.Load (Partition, Status);
    pragma Assert (Status = FBVBS.ABI.OK);

    FBVBS.Partitions.Start (Partition, Status);
    pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.Partitions.Quiesce (Partition, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.Partitions.Resume (Partition, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.Partitions.Fault (Partition, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.Partitions.Recover (Partition, Has_Image => True, Status => Status);
   pragma Assert (Status = FBVBS.ABI.OK);

    FBVBS.KCI.Initialize (Verify_State);
    FBVBS.UVS.Require_Artifact_Approval
      (Manifest_Set,
       Artifact_Object_Id => 16#3000#,
       Manifest_Object_Id => 16#2000#,
       Status             => Status);
    pragma Assert (Status = FBVBS.ABI.Signature_Invalid);
    FBVBS.UVS.Verify_Artifact
      (Manifest_Set,
       Artifact_Object_Id => 16#3000#,
       Manifest_Object_Id => 16#2000#,
       Tail_Zero          => True,
       Hash_Matches       => True,
       Status             => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.UVS.Require_Artifact_Approval
      (Manifest_Set,
       Artifact_Object_Id => 16#3000#,
       Manifest_Object_Id => 16#2000#,
       Status             => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.KCI.Verify_Module (Verify_State, 16#3000#, 16#2000#, 1, Status);
    pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.KCI.Set_WX (Verify_State, 16#3000#, Writable => False, Executable => True, Status => Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.KCI.Pin_CR0 (Verify_State, 16#1#, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.KCI.Intercept_MSR (Verify_State, FBVBS.ABI.KCI_MSR_EFER, Enable => True, Status => Status);
   pragma Assert (Status = FBVBS.ABI.OK);

    FBVBS.KSI.Initialize (Target_Set);
    FBVBS.KSI_Shadow.Initialize (Shadow_State);
    FBVBS.KSI.Create_Target_Set
     (Target_Set,
      16#300000#,
      16#11000#,
      16#13000#,
      2,
      Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.KSI.Register_Tier_B_Object
     (State                  => Target_Set,
      Object_Id              => 16#11000#,
      Guest_Physical_Address => 16#11000#,
      Size                   => FBVBS.ABI.Page_Size,
      Protection_Class       => FBVBS.ABI.KSI_Class_UCRED,
      Status                 => Status);
   pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.KSI.Register_Tier_B_Object
      (State                  => Target_Set,
       Object_Id              => 16#13000#,
       Guest_Physical_Address => 16#13000#,
       Size                   => FBVBS.ABI.Page_Size,
       Protection_Class       => FBVBS.ABI.KSI_Class_UCRED,
       Status                 => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.KSI.Register_Target_Object
      (State                  => Target_Set,
       Object_Id              => 16#12000#,
       Guest_Physical_Address => 16#12000#,
       Size                   => FBVBS.ABI.Page_Size,
       Status                 => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.KSI.Modify_Tier_B_Object (Target_Set, 16#11000#, 64, Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.KSI.Modify_Tier_B_Object (Target_Set, 16#12000#, 64, Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_State);
     FBVBS.KSI.Register_Pointer (Target_Set, 16#12000#, Status);
      pragma Assert (Status = FBVBS.ABI.OK);
     FBVBS.KSI.Replace_Tier_B_Object (Target_Set, 16#13000#, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Target_Set.Active_Target_Object_Id = 16#13000#);
     FBVBS.KSI_Shadow.Prepare_Update
       (Targets             => Target_Set,
        State               => Shadow_State,
        Shadow_Object_Id    => 16#14000#,
        Candidate_Object_Id => 16#11000#,
        Observed_RIP        => FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile),
        Allowed_Primary     => FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile),
        Allowed_Secondary   => FBVBS.ABI.Secondary_Callsite (FBVBS_Host_Profile),
        Status              => Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     FBVBS.KSI_Shadow.Pause_Writers (Shadow_State, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     FBVBS.KSI_Shadow.Open_Write_Window (Shadow_State, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     FBVBS.KSI_Shadow.Commit_Update (Target_Set, Shadow_State, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Target_Set.Active_Target_Object_Id = 16#11000#);
     pragma Assert (not Shadow_State.Update_In_Progress);
     FBVBS.KSI_Shadow.Prepare_Update
       (Targets             => Target_Set,
        State               => Shadow_State,
        Shadow_Object_Id    => 16#15000#,
        Candidate_Object_Id => 16#DEAD#,
        Observed_RIP        => 16#BAD0#,
        Allowed_Primary     => FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile),
        Allowed_Secondary   => FBVBS.ABI.Secondary_Callsite (FBVBS_Host_Profile),
        Status              => Status);
     pragma Assert (Status = FBVBS.ABI.Callsite_Rejected);
      declare
         Setuid_Targets : FBVBS.ABI.Target_Set_Record;
         Measured_Hash  : FBVBS.ABI.Hash_Buffer := (others => 0);
         Ucred_Object_Id : FBVBS.ABI.Handle := 0;
      begin
        FBVBS.KSI.Initialize (Setuid_Targets);
        FBVBS.KSI.Create_Target_Set
          (Setuid_Targets,
           16#310000#,
           16#21000#,
           16#22000#,
           2,
           Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        FBVBS.KSI.Register_Tier_B_Object
          (State                  => Setuid_Targets,
           Object_Id              => 16#21000#,
           Guest_Physical_Address => 16#21000#,
           Size                   => FBVBS.ABI.Page_Size,
           Protection_Class       => FBVBS.ABI.KSI_Class_UCRED,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        FBVBS.KSI.Register_Tier_B_Object
          (State                  => Setuid_Targets,
           Object_Id              => 16#22000#,
           Guest_Physical_Address => 16#22000#,
           Size                   => FBVBS.ABI.Page_Size,
           Protection_Class       => FBVBS.ABI.KSI_Class_MAC,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        FBVBS.KSI.Register_Tier_B_Object
          (State                  => Setuid_Targets,
           Object_Id              => 16#23000#,
           Guest_Physical_Address => 16#23000#,
           Size                   => FBVBS.ABI.Page_Size,
           Protection_Class       => FBVBS.ABI.KSI_Class_Prison,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        FBVBS.KSI.Allocate_Ucred
          (State                    => Setuid_Targets,
           Requested_UID            => 1000,
           Requested_GID            => 1000,
           Prison_Object_Id         => 16#23000#,
           Template_Ucred_Object_Id => 16#21000#,
           Ucred_Object_Id          => Ucred_Object_Id,
           Status                   => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        pragma Assert (Ucred_Object_Id /= 0);

        FBVBS.KSI.Validate_Setuid
          (State                  => Setuid_Targets,
           Operation_Class        => FBVBS.ABI.KSI_Operation_Setuid_Family,
           Valid_Mask             => FBVBS.ABI.KSI_Valid_EUID,
           FSID                   => 0,
           File_Id                => 0,
           Measured_Hash          => (others => 0),
           Requested_RUID         => 0,
           Requested_EUID         => 0,
           Requested_SUID         => 0,
           Requested_RGID         => 0,
           Requested_EGID         => 0,
           Requested_SGID         => 0,
           Caller_Ucred_Object_Id => Ucred_Object_Id,
           Jail_Context_Id        => 0,
           MAC_Context_Id         => 0,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.OK);

        FBVBS.KSI.Validate_Setuid
          (State                  => Setuid_Targets,
           Operation_Class        => FBVBS.ABI.KSI_Operation_Setuid_Family,
           Valid_Mask             => FBVBS.ABI.KSI_Valid_EGID,
           FSID                   => 0,
           File_Id                => 0,
           Measured_Hash          => (others => 0),
           Requested_RUID         => 0,
           Requested_EUID         => 0,
           Requested_SUID         => 0,
           Requested_RGID         => 0,
           Requested_EGID         => 0,
           Requested_SGID         => 0,
           Caller_Ucred_Object_Id => Ucred_Object_Id,
           Jail_Context_Id        => 0,
           MAC_Context_Id         => 0,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.Policy_Denied);

        Measured_Hash (0) := 16#33#;
        Measured_Hash (47) := 16#CC#;
        FBVBS.KSI.Validate_Setuid
          (State                  => Setuid_Targets,
           Operation_Class        => FBVBS.ABI.KSI_Operation_Exec_Elevation,
           Valid_Mask             => FBVBS.ABI.KSI_Valid_EUID,
           FSID                   => 1,
           File_Id                => 2,
           Measured_Hash          => Measured_Hash,
           Requested_RUID         => 0,
           Requested_EUID         => 0,
           Requested_SUID         => 0,
           Requested_RGID         => 0,
           Requested_EGID         => 0,
           Requested_SGID         => 0,
           Caller_Ucred_Object_Id => Ucred_Object_Id,
           Jail_Context_Id        => 0,
           MAC_Context_Id         => 16#22000#,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.OK);

        FBVBS.KSI.Validate_Setuid
          (State                  => Setuid_Targets,
           Operation_Class        => FBVBS.ABI.KSI_Operation_Exec_Elevation,
           Valid_Mask             => FBVBS.ABI.KSI_Valid_EUID,
           FSID                   => 1,
           File_Id                => 2,
           Measured_Hash          => Measured_Hash,
           Requested_RUID         => 0,
           Requested_EUID         => 0,
           Requested_SUID         => 0,
           Requested_RGID         => 0,
           Requested_EGID         => 0,
           Requested_SGID         => 0,
           Caller_Ucred_Object_Id => Ucred_Object_Id,
           Jail_Context_Id        => 16#22000#,
           MAC_Context_Id         => 0,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.Policy_Denied);
        FBVBS.KSI.Unregister_Object (Setuid_Targets, Ucred_Object_Id, Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        FBVBS.KSI.Validate_Setuid
          (State                  => Setuid_Targets,
           Operation_Class        => FBVBS.ABI.KSI_Operation_Setuid_Family,
           Valid_Mask             => FBVBS.ABI.KSI_Valid_EUID,
           FSID                   => 0,
           File_Id                => 0,
           Measured_Hash          => (others => 0),
           Requested_RUID         => 0,
           Requested_EUID         => 0,
           Requested_SUID         => 0,
           Requested_RGID         => 0,
           Requested_EGID         => 0,
           Requested_SGID         => 0,
           Caller_Ucred_Object_Id => Ucred_Object_Id,
           Jail_Context_Id        => 0,
           MAC_Context_Id         => 0,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.Not_Found);
      end;

    FBVBS.IKS.Initialize (Signing_Key);
   FBVBS.IKS.Import_Key
     (Signing_Key,
      16#400000#,
      FBVBS.ABI.Ed25519,
      FBVBS.ABI.IKS_Op_Sign or FBVBS.ABI.IKS_Op_Derive,
      32,
      Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.IKS.Sign (Signing_Key, Status);
   pragma Assert (Status = FBVBS.ABI.OK);

   FBVBS.IKS.Initialize (Exchange_Key);
   FBVBS.IKS.Import_Key
     (Exchange_Key,
      16#400001#,
      FBVBS.ABI.X25519,
      FBVBS.ABI.IKS_Op_Key_Exchange or FBVBS.ABI.IKS_Op_Derive,
      32,
      Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.IKS.Key_Exchange (Exchange_Key, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.IKS.Derive (Exchange_Key, Status);
   pragma Assert (Status = FBVBS.ABI.OK);

   FBVBS.SKS.Initialize (Dek_State);
   FBVBS.SKS.Import_DEK (Dek_State, 16#500000#, 1, 32, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.SKS.Process_Batch (Dek_State, 2, Page_Aligned => True, Status => Status);
   pragma Assert (Status = FBVBS.ABI.OK);

     FBVBS.UVS.Verify_Manifest_Set
       (Manifest_Set,
        Verified_Manifest_Set_Id => 16#600001#,
        Manifest_Count           => 5,
        Revoked_Object_Id        => 0,
        Signatures_Valid         => True,
        Not_Revoked              => True,
        Generation_Valid         => True,
        Rollback_Free            => True,
        Dependencies_Satisfied   => True,
        Snapshot_Consistent      => True,
        Freshness_Valid          => True,
        Status                   => Status);
     pragma Assert (Status = FBVBS.ABI.Invalid_State);
    FBVBS.UVS.Verify_Artifact
      (Manifest_Set,
       Artifact_Object_Id => 16#3000#,
       Manifest_Object_Id => 16#2000#,
       Tail_Zero          => True,
       Hash_Matches       => True,
       Status             => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    FBVBS.UVS.Check_Revocation
      (Manifest_Set,
       Object_Id    => 16#2000#,
       Known_Object => True,
       Revoked      => Revoked,
       Status       => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    pragma Assert (not Revoked);
    FBVBS.UVS.Initialize (Manifest_Set);
    FBVBS.UVS.Verify_Manifest_Set
      (Manifest_Set,
       Verified_Manifest_Set_Id => 16#600002#,
       Manifest_Count           => 5,
       Revoked_Object_Id        => 16#2000#,
       Signatures_Valid         => True,
       Not_Revoked              => False,
       Generation_Valid         => True,
       Rollback_Free            => True,
       Dependencies_Satisfied   => True,
       Snapshot_Consistent      => True,
       Freshness_Valid          => True,
       Status                   => Status);
    pragma Assert (Status = FBVBS.ABI.Revoked);
    pragma Assert (Manifest_Set.Revoked_Object_Id = 16#2000#);

   FBVBS.Platform.Initialize (Caps, IOMMU_Domain);
   FBVBS.Platform.Check_VM_Create (Caps, Status);
   pragma Assert (Status = FBVBS.ABI.Not_Supported_On_Platform);
   FBVBS.Platform.Configure (Caps, Has_HLAT => True, Has_IOMMU => True);
   FBVBS.Platform.Check_VM_Create (Caps, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.Platform.Attach_Device (Caps, 1, Next_Domain, 16#D000#, IOMMU_Domain, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   pragma Assert (IOMMU_Domain.In_Use);
   pragma Assert (IOMMU_Domain.Attached_Device_Count = 1);
   FBVBS.Platform.Release_Device (1, 16#D000#, IOMMU_Domain, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   pragma Assert (not IOMMU_Domain.In_Use);

   FBVBS.Commands.Initialize (Command_Tracker);
   FBVBS.Commands.Begin_Dispatch (Command_Tracker, Command_State, 0, 1, 16#AA#, Status);
   pragma Assert (Status = FBVBS.ABI.OK);
   FBVBS.Commands.Finish_Dispatch (Command_State, FBVBS.ABI.OK, 0);
   pragma Assert (Command_State = FBVBS.ABI.Command_Completed);
    Command_State := FBVBS.ABI.Command_Ready;
    FBVBS.Commands.Begin_Dispatch (Command_Tracker, Command_State, 0, 1, 16#BB#, Status);
    pragma Assert (Status = FBVBS.ABI.Replay_Detected);
     FBVBS.Commands.Validate_Separate_Output
       (Partition,
        Output_Page_Aligned       => True,
        Mapping_Writable          => True,
       Reserved_Sharing_Writable => False,
       Output_Length_Max         => 16,
       Required_Length           => 8,
       Status                    => Status);
    pragma Assert (Status = FBVBS.ABI.Invalid_Parameter);
    FBVBS.Commands.Validate_Separate_Output
      (Partition,
       Output_Page_Aligned       => True,
       Mapping_Writable          => True,
       Reserved_Sharing_Writable => True,
       Output_Length_Max         => 16,
        Required_Length           => 8,
        Status                    => Status);
     pragma Assert (Status = FBVBS.ABI.OK);

     declare
        Dispatch_Tracker  : FBVBS.ABI.Command_Tracker_Record;
        Dispatch_State    : FBVBS.ABI.Command_State := FBVBS.ABI.Command_Ready;
        Dispatch_Service_Caller : FBVBS.ABI.Partition_Descriptor :=
          (In_Use             => True,
           Partition_Id       => 16#45#,
           Kind               => FBVBS.ABI.Partition_Trusted_Service,
           State              => FBVBS.ABI.Runnable,
           Measurement_Epoch  => 1,
           Service_Kind       => FBVBS.ABI.Service_KCI,
           Memory_Limit_Bytes => 0,
           Capability_Mask    => 0,
           Mapped_Bytes       => 0,
           Last_Fault_Code  => 0,
           Last_Source_Component => 0,
           Last_Fault_Detail0 => 0,
           Last_Fault_Detail1 => 0);
        Dispatch_KSI_Caller : FBVBS.ABI.Partition_Descriptor :=
          (In_Use             => True,
           Partition_Id       => 16#46#,
           Kind               => FBVBS.ABI.Partition_Trusted_Service,
           State              => FBVBS.ABI.Runnable,
           Measurement_Epoch  => 1,
           Service_Kind       => FBVBS.ABI.Service_KSI,
           Memory_Limit_Bytes => 0,
           Capability_Mask    => 0,
           Mapped_Bytes       => 0,
           Last_Fault_Code  => 0,
           Last_Source_Component => 0,
           Last_Fault_Detail0 => 0,
           Last_Fault_Detail1 => 0);
        Dispatch_IKS_Caller : FBVBS.ABI.Partition_Descriptor :=
          (In_Use             => True,
           Partition_Id       => 16#47#,
           Kind               => FBVBS.ABI.Partition_Trusted_Service,
           State              => FBVBS.ABI.Runnable,
           Measurement_Epoch  => 1,
           Service_Kind       => FBVBS.ABI.Service_IKS,
           Memory_Limit_Bytes => 0,
           Capability_Mask    => 0,
           Mapped_Bytes       => 0,
           Last_Fault_Code  => 0,
           Last_Source_Component => 0,
           Last_Fault_Detail0 => 0,
           Last_Fault_Detail1 => 0);
        Dispatch_SKS_Caller : FBVBS.ABI.Partition_Descriptor :=
          (In_Use             => True,
           Partition_Id       => 16#48#,
           Kind               => FBVBS.ABI.Partition_Trusted_Service,
           State              => FBVBS.ABI.Runnable,
           Measurement_Epoch  => 1,
           Service_Kind       => FBVBS.ABI.Service_SKS,
           Memory_Limit_Bytes => 0,
           Capability_Mask    => 0,
           Mapped_Bytes       => 0,
           Last_Fault_Code  => 0,
           Last_Source_Component => 0,
           Last_Fault_Detail0 => 0,
           Last_Fault_Detail1 => 0);
        Dispatch_Log      : FBVBS.ABI.Log_State_Record;
        Dispatch_Caps     : FBVBS.ABI.Platform_Capabilities :=
          (Has_HLAT => True, Has_IOMMU => True);
        Dispatch_Domain   : FBVBS.ABI.IOMMU_Domain_Record :=
          (In_Use                => True,
           Domain_Id             => 16#6600#,
           Owner_Partition_Id    => 16#44#,
           Attached_Device_Count => 1);
        Dispatch_Artifact : FBVBS.ABI.Artifact_Catalog_Entry_Record :=
          (Object_Id => 16#7777#,
           Object_Kind => FBVBS.ABI.Artifact_Module,
           Related_Index => 3);
        Dispatch_Verify   : FBVBS.ABI.Verification_Record;
        Dispatch_Manifest : FBVBS.ABI.Manifest_Set_Record;
        Dispatch_Target   : FBVBS.ABI.Partition_Descriptor;
        Dispatch_VCPU     : FBVBS.ABI.VCPU_Record;
        Dispatch_Memory_Object : FBVBS.ABI.Memory_Object_Record;
         Dispatch_Next_Object_Id : FBVBS.ABI.Handle := 16#8800#;
         Dispatch_Next_Partition_Id : FBVBS.ABI.Handle := 16#4400#;
        Dispatch_Target_Set_State : FBVBS.ABI.Target_Set_Record;
        Dispatch_Key_State : FBVBS.ABI.Key_Record;
        Dispatch_Dek_State : FBVBS.ABI.Dek_Record;
        Dispatch_Next_Target_Set_Id : FBVBS.ABI.Handle := 16#9900#;
        Dispatch_Next_Key_Handle : FBVBS.ABI.Handle := 16#A000#;
        Dispatch_Next_Dek_Handle : FBVBS.ABI.Handle := 16#B000#;
        Dispatch_Ucred_Object_Id : FBVBS.ABI.Handle := 0;
        Dispatch_Result   : FBVBS.ABI.Dispatch_Result_Record;
        Dispatch_Request  : FBVBS.ABI.Dispatch_Request_Record;
     begin
        FBVBS.Commands.Initialize (Dispatch_Tracker);
        FBVBS.Logging.Initialize (Dispatch_Log, 1, 2, Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        FBVBS.KCI.Initialize (Dispatch_Verify);
        FBVBS.UVS.Initialize (Dispatch_Manifest);
        FBVBS.Partitions.Initialize (Dispatch_Target);
        FBVBS.Partitions.Create (Dispatch_Target, 16#44#, Status);
        pragma Assert (Status = FBVBS.ABI.OK);
         Dispatch_Target.Memory_Limit_Bytes := 8192;
         Dispatch_Target.Capability_Mask :=
           FBVBS.ABI.Capability_Memory_Map or FBVBS.ABI.Capability_Memory_Set_Permission;
         Dispatch_Target.Kind := FBVBS.ABI.Partition_Guest_VM;
         FBVBS.VMX.Initialize (Dispatch_VCPU);
         FBVBS.VMX.Start (Dispatch_VCPU);
        FBVBS.Memory.Initialize_Object (Dispatch_Memory_Object);
        FBVBS.KSI.Initialize (Dispatch_Target_Set_State);
        FBVBS.IKS.Initialize (Dispatch_Key_State);
        FBVBS.SKS.Initialize (Dispatch_Dek_State);
        pragma Assert (Dispatch_VCPU.State = FBVBS.ABI.VCPU_Runnable);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_UVS_Verify_Manifest_Set;
        Dispatch_Request.Caller_Sequence := 1;
        Dispatch_Request.Caller_Nonce := 16#A1#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Verified_Manifest_Set_Id := 16#6000#;
        Dispatch_Request.Manifest_Count := 2;
        Dispatch_Request.Signatures_Valid := True;
        Dispatch_Request.Not_Revoked := True;
        Dispatch_Request.Generation_Valid := True;
        Dispatch_Request.Rollback_Free := True;
        Dispatch_Request.Dependencies_Satisfied := True;
        Dispatch_Request.Snapshot_Consistent := True;
        Dispatch_Request.Freshness_Valid := True;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Tracker          => Dispatch_Tracker,
           Command_State    => Dispatch_State,
           Caller           => Host_Partition,
           Target_Partition => Dispatch_Target,
           Host_Profile     => FBVBS_Host_Profile,
           Caps             => Dispatch_Caps,
           Domain           => Dispatch_Domain,
           Artifact         => Dispatch_Artifact,
            Log_State        => Dispatch_Log,
            Verify_State     => Dispatch_Verify,
            Manifest_State   => Dispatch_Manifest,
            VCPU             => Dispatch_VCPU,
            Memory_Object    => Dispatch_Memory_Object,
            Next_Object_Id   => Dispatch_Next_Object_Id,
            Next_Partition_Id => Dispatch_Next_Partition_Id,
            Target_Set_State => Dispatch_Target_Set_State,
            Key_State        => Dispatch_Key_State,
            Dek_State        => Dispatch_Dek_State,
            Next_Target_Set_Id => Dispatch_Next_Target_Set_Id,
            Next_Key_Handle    => Dispatch_Next_Key_Handle,
            Next_Dek_Handle    => Dispatch_Next_Dek_Handle,
            Request          => Dispatch_Request,
            Result           => Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_State = FBVBS.ABI.Command_Completed);
        pragma Assert (Dispatch_Manifest.In_Use);
        pragma Assert (Dispatch_Result.Failure_Bitmap = 0);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_UVS_Verify_Artifact;
        Dispatch_Request.Caller_Sequence := 2;
        Dispatch_Request.Caller_Nonce := 16#A2#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Artifact_Object_Id := 16#1000#;
        Dispatch_Request.Manifest_Object_Id := 16#2000#;
        Dispatch_Request.Tail_Zero := True;
        Dispatch_Request.Hash_Matches := True;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Manifest.Approved_Artifact_Object_Id = 16#1000#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Measure;
        Dispatch_Request.Caller_Sequence := 3;
        Dispatch_Request.Caller_Nonce := 16#A3#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Approval_Present := True;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.State = FBVBS.ABI.Measured);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KCI_Verify_Module;
        Dispatch_Request.Caller_Sequence := 4;
        Dispatch_Request.Caller_Nonce := 16#A4#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Module_Object_Id := 16#1000#;
        Dispatch_Request.Manifest_Object_Id := 16#2000#;
        Dispatch_Request.Generation := 1;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Verify.Approved_Module_Object_Id = 16#1000#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KCI_Set_WX;
        Dispatch_Request.Caller_Sequence := 5;
        Dispatch_Request.Caller_Nonce := 16#A5#;
        Dispatch_Request.Module_Object_Id := 16#1000#;
        Dispatch_Request.Permissions :=
          FBVBS.ABI.Memory_Permission_Read or FBVBS.ABI.Memory_Permission_Execute;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_Service_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KCI_Pin_CR;
        Dispatch_Request.Caller_Sequence := 6;
        Dispatch_Request.Caller_Nonce := 16#A6#;
        Dispatch_Request.Pin_Register := 0;
        Dispatch_Request.Pin_Mask := 16#8001_0033#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_Service_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Verify.Pinned_CR0_Mask = 16#8001_0033#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KCI_Intercept_MSR;
        Dispatch_Request.Caller_Sequence := 7;
        Dispatch_Request.Caller_Nonce := 16#A7#;
        Dispatch_Request.MSR_Address := FBVBS.ABI.KCI_MSR_EFER;
        Dispatch_Request.Enable := True;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_Service_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Verify.Intercepted_MSR_Count = 1);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Inject_Interrupt;
         Dispatch_Request.Caller_Sequence := 8;
         Dispatch_Request.Caller_Nonce := 16#A8#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Interrupt_Vector := 48;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_VCPU.Interrupt_Pending);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Run;
         Dispatch_Request.Caller_Sequence := 9;
         Dispatch_Request.Caller_Nonce := 16#A9#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Has_HLAT := True;
        Dispatch_Request.Mapped_Bytes := 4096;
        Dispatch_Request.VCPU_Id := 0;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.VM_Result.Exit_Reason = FBVBS.ABI.Exit_External_Interrupt);
        pragma Assert (Dispatch_Result.Actual_Output_Length = 8);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Audit_Get_Boot_Id;
        Dispatch_Request.Caller_Sequence := 10;
        Dispatch_Request.Caller_Nonce := 16#AA#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Boot_Id_Hi = 1);
        pragma Assert (Dispatch_Result.Boot_Id_Lo = 2);
        pragma Assert (Dispatch_Log.Max_Readable_Sequence = 10);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Diag_Get_Capabilities;
        Dispatch_Request.Caller_Sequence := 11;
        Dispatch_Request.Caller_Nonce := 16#AB#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Diag_Capabilities.Capability_Bitmap0 = FBVBS.ABI.Cap_Bitmap0_HLAT);
        pragma Assert (Dispatch_Result.Diag_Capabilities.Capability_Bitmap1 = FBVBS.ABI.Cap_Bitmap1_IOMMU);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Diag_Get_Partition_List;
        Dispatch_Request.Caller_Sequence := 12;
        Dispatch_Request.Caller_Nonce := 16#AC#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Diag_Partition.Count = 1);
        pragma Assert (Dispatch_Result.Diag_Partition.Partition_Id = 16#44#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Diag_Get_Artifact_List;
        Dispatch_Request.Caller_Sequence := 13;
        Dispatch_Request.Caller_Nonce := 16#AD#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Diag_Artifact.Count = 1);
        pragma Assert (Dispatch_Result.Diag_Artifact.Object_Id = 16#7777#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Diag_Get_Device_List;
        Dispatch_Request.Caller_Sequence := 14;
        Dispatch_Request.Caller_Nonce := 16#AE#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Device_Id := 16#D000#;
        Dispatch_Request.Device_Segment := 0;
        Dispatch_Request.Device_Bus := 29;
        Dispatch_Request.Device_Slot_Function := 1;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Diag_Device.Count = 1);
        pragma Assert (Dispatch_Result.Diag_Device.Device_Id = 16#D000#);
        pragma Assert (Dispatch_Log.Max_Readable_Sequence = 14);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Allocate_Object;
        Dispatch_Request.Caller_Sequence := 15;
        Dispatch_Request.Caller_Nonce := 16#AF#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Size := 4096;
        Dispatch_Request.Object_Flags := FBVBS.ABI.Memory_Object_Flag_Guest_Memory;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Memory_Object_Id = 16#8800#);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Map;
         Dispatch_Request.Caller_Sequence := 16;
         Dispatch_Request.Caller_Nonce := 16#B0#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
         Dispatch_Request.Memory_Object_Id := 16#8800#;
         Dispatch_Request.Guest_Physical_Address := 16#2000#;
         Dispatch_Request.Size := 4096;
         Dispatch_Request.Permissions :=
           FBVBS.ABI.Memory_Permission_Read or FBVBS.ABI.Memory_Permission_Execute;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.Mapped_Bytes = 4096);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Set_Permission;
        Dispatch_Request.Caller_Sequence := 17;
        Dispatch_Request.Caller_Nonce := 16#B1#;
        Dispatch_Request.Permissions := FBVBS.ABI.Memory_Permission_Read or FBVBS.ABI.Memory_Permission_Execute;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_Service_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Map_Memory;
         Dispatch_Request.Caller_Sequence := 18;
         Dispatch_Request.Caller_Nonce := 16#B2#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Memory_Object_Id := 16#8800#;
         Dispatch_Request.Guest_Physical_Address := 16#3000#;
         Dispatch_Request.Size := 4096;
         Dispatch_Request.Permissions := FBVBS.ABI.Memory_Permission_Read;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.Mapped_Bytes = 8192);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Release_Object;
        Dispatch_Request.Caller_Sequence := 19;
        Dispatch_Request.Caller_Nonce := 16#B3#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.Resource_Busy);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Register_Shared;
        Dispatch_Request.Caller_Sequence := 20;
        Dispatch_Request.Caller_Nonce := 16#B4#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Peer_Partition_Id := 0;
        Dispatch_Request.Permissions := FBVBS.ABI.Memory_Permission_Read;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Shared_Object_Id = 16#8800#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Unregister_Shared;
        Dispatch_Request.Caller_Sequence := 21;
        Dispatch_Request.Caller_Nonce := 16#B5#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Memory_Object.Shared_Count = 0);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Unmap;
        Dispatch_Request.Caller_Sequence := 22;
        Dispatch_Request.Caller_Nonce := 16#B6#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Size := 4096;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.Mapped_Bytes = 4096);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Unmap;
        Dispatch_Request.Caller_Sequence := 23;
        Dispatch_Request.Caller_Nonce := 16#B7#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        Dispatch_Request.Size := 4096;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.Mapped_Bytes = 0);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Memory_Release_Object;
        Dispatch_Request.Caller_Sequence := 24;
        Dispatch_Request.Caller_Nonce := 16#B8#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (not Dispatch_Memory_Object.Allocated);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Load_Image;
        Dispatch_Request.Caller_Sequence := 25;
        Dispatch_Request.Caller_Nonce := 16#B9#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.State = FBVBS.ABI.Loaded);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Start;
        Dispatch_Request.Caller_Sequence := 26;
        Dispatch_Request.Caller_Nonce := 16#BA#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.State = FBVBS.ABI.Runnable);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Get_Status;
        Dispatch_Request.Caller_Sequence := 27;
        Dispatch_Request.Caller_Nonce := 16#BB#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Partition_Status.State = FBVBS.ABI.Runnable);
        pragma Assert (Dispatch_Result.Partition_Status.Measurement_Epoch = 1);
        pragma Assert (Dispatch_Result.Actual_Output_Length = 16);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Quiesce;
        Dispatch_Request.Caller_Sequence := 28;
        Dispatch_Request.Caller_Nonce := 16#BC#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.State = FBVBS.ABI.Quiesced);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Get_Status;
        Dispatch_Request.Caller_Sequence := 29;
        Dispatch_Request.Caller_Nonce := 16#BD#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Partition_Status.State = FBVBS.ABI.Quiesced);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Partition_Resume;
        Dispatch_Request.Caller_Sequence := 30;
        Dispatch_Request.Caller_Nonce := 16#BE#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Target.State = FBVBS.ABI.Runnable);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_Audit_Get_Mirror_Info;
        Dispatch_Request.Caller_Sequence := 31;
        Dispatch_Request.Caller_Nonce := 16#BF#;
        Dispatch_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Audit_Mirror.Ring_GPA = FBVBS.ABI.Mirror_Log_Ring_GPA);
        pragma Assert (Dispatch_Result.Audit_Mirror.Ring_Size = FBVBS.ABI.Log_Ring_Total_Size);
        pragma Assert (Dispatch_Result.Audit_Mirror.Record_Size = FBVBS.ABI.Log_Record_Size);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Get_VCPU_Status;
         Dispatch_Request.Caller_Sequence := 32;
         Dispatch_Request.Caller_Nonce := 16#C0#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.VCPU_Id := 0;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.VCPU_State_Value = FBVBS.ABI.VCPU_Runnable);
        pragma Assert (Dispatch_Result.Actual_Output_Length = 8);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Set_Register;
         Dispatch_Request.Caller_Sequence := 33;
         Dispatch_Request.Caller_Nonce := 16#C1#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Register_Id := FBVBS.ABI.VM_Reg_RIP;
        Dispatch_Request.Register_Value := FBVBS.ABI.Synthetic_Exit_RIP_MMIO;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_VCPU.RIP = FBVBS.ABI.Synthetic_Exit_RIP_MMIO);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Get_Register;
         Dispatch_Request.Caller_Sequence := 34;
         Dispatch_Request.Caller_Nonce := 16#C2#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Register_Id := FBVBS.ABI.VM_Reg_RIP;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Register_Value = FBVBS.ABI.Synthetic_Exit_RIP_MMIO);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Set_Register;
         Dispatch_Request.Caller_Sequence := 35;
         Dispatch_Request.Caller_Nonce := 16#C3#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Register_Id := FBVBS.ABI.VM_Reg_CR3;
        Dispatch_Request.Register_Value := 16#1234#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.Permission_Denied);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_VM_Get_Register;
         Dispatch_Request.Caller_Sequence := 36;
         Dispatch_Request.Caller_Nonce := 16#C4#;
         Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;
         Dispatch_Request.Register_Id := FBVBS.ABI.VM_Reg_CR3;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Host_Partition,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Register_Value = 0);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Create_Target_Set;
         Dispatch_Request.Caller_Sequence := 37;
         Dispatch_Request.Caller_Nonce := 16#C5#;
         Dispatch_Request.Target_Count := 2;
         Dispatch_Request.First_Target_Object_Id := 16#11000#;
         Dispatch_Request.Second_Target_Object_Id := 16#13000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Target_Set_Id = 16#9900#);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Register_Tier_B;
         Dispatch_Request.Caller_Sequence := 38;
         Dispatch_Request.Caller_Nonce := 16#C6#;
         Dispatch_Request.Object_Id := 16#11000#;
         Dispatch_Request.Guest_Physical_Address := 16#11000#;
         Dispatch_Request.Size := FBVBS.ABI.Page_Size;
         Dispatch_Request.Protection_Class := FBVBS.ABI.KSI_Class_UCRED;
         FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Register_Tier_B;
         Dispatch_Request.Caller_Sequence := 39;
         Dispatch_Request.Caller_Nonce := 16#C7#;
         Dispatch_Request.Object_Id := 16#13000#;
         Dispatch_Request.Guest_Physical_Address := 16#13000#;
         Dispatch_Request.Size := FBVBS.ABI.Page_Size;
         Dispatch_Request.Protection_Class := FBVBS.ABI.KSI_Class_UCRED;
         FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Modify_Tier_B;
         Dispatch_Request.Caller_Sequence := 40;
         Dispatch_Request.Caller_Nonce := 16#C8#;
         Dispatch_Request.Object_Id := 16#11000#;
         Dispatch_Request.Patch_Length := 64;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Register_Tier_A;
         Dispatch_Request.Caller_Sequence := 41;
         Dispatch_Request.Caller_Nonce := 16#C9#;
         Dispatch_Request.Object_Id := 16#12000#;
         Dispatch_Request.Guest_Physical_Address := 16#12000#;
         Dispatch_Request.Size := FBVBS.ABI.Page_Size;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
            Dispatch_Request,
            Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Register_Pointer;
        Dispatch_Request.Caller_Sequence := 42;
        Dispatch_Request.Caller_Nonce := 16#CA#;
         Dispatch_Request.Target_Set_Id := 16#9900#;
         Dispatch_Request.Pointer_Object_Id := 16#12000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Register_Tier_B;
        Dispatch_Request.Caller_Sequence := 43;
        Dispatch_Request.Caller_Nonce := 16#CB#;
         Dispatch_Request.Object_Id := 16#14000#;
         Dispatch_Request.Guest_Physical_Address := 16#14000#;
         Dispatch_Request.Size := FBVBS.ABI.Page_Size;
         Dispatch_Request.Protection_Class := FBVBS.ABI.KSI_Class_Prison;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Allocate_Ucred;
        Dispatch_Request.Caller_Sequence := 44;
        Dispatch_Request.Caller_Nonce := 16#CC#;
        Dispatch_Request.Requested_UID := 1000;
        Dispatch_Request.Requested_GID := 1000;
        Dispatch_Request.Prison_Object_Id := 16#14000#;
        Dispatch_Request.Template_Ucred_Object_Id := 16#11000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        Dispatch_Ucred_Object_Id := Dispatch_Result.Ucred_Object_Id;
        pragma Assert (Dispatch_Ucred_Object_Id /= 0);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Validate_Setuid;
        Dispatch_Request.Caller_Sequence := 45;
        Dispatch_Request.Caller_Nonce := 16#CD#;
        Dispatch_Request.Operation_Class := FBVBS.ABI.KSI_Operation_Setuid_Family;
        Dispatch_Request.Valid_Mask := FBVBS.ABI.KSI_Valid_EUID;
        Dispatch_Request.Caller_Ucred_Object_Id := Dispatch_Ucred_Object_Id;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Verdict = 1);

        Dispatch_Request := (others => <>);
         Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Replace_Tier_B_Object;
         Dispatch_Request.Caller_Sequence := 46;
         Dispatch_Request.Caller_Nonce := 16#CE#;
         Dispatch_Request.Object_Id := 16#11000#;
         Dispatch_Request.New_Object_Id := 16#13000#;
         Dispatch_Request.Pointer_Object_Id := 16#12000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
            Dispatch_Request,
            Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
         pragma Assert (Dispatch_Target_Set_State.Active_Target_Object_Id = 16#13000#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Unregister_Object;
        Dispatch_Request.Caller_Sequence := 47;
        Dispatch_Request.Caller_Nonce := 16#CF#;
        Dispatch_Request.Object_Id := Dispatch_Ucred_Object_Id;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_KSI_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_IKS_Import_Key;
        Dispatch_Request.Caller_Sequence := 48;
        Dispatch_Request.Caller_Nonce := 16#D0#;
        Dispatch_Request.Requested_Key_Kind := FBVBS.ABI.Ed25519;
        Dispatch_Request.Allowed_Ops := FBVBS.ABI.IKS_Op_Sign or FBVBS.ABI.IKS_Op_Derive;
        Dispatch_Request.Key_Length := 32;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_IKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Key_Handle = 16#A000#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_IKS_Sign;
        Dispatch_Request.Caller_Sequence := 49;
        Dispatch_Request.Caller_Nonce := 16#CC#;
        Dispatch_Request.Key_Handle := 16#A000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_IKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Returned_Length = 64);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_IKS_Destroy_Key;
        Dispatch_Request.Caller_Sequence := 50;
        Dispatch_Request.Caller_Nonce := 16#CD#;
        Dispatch_Request.Key_Handle := 16#A000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_IKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_IKS_Import_Key;
        Dispatch_Request.Caller_Sequence := 51;
        Dispatch_Request.Caller_Nonce := 16#CE#;
        Dispatch_Request.Requested_Key_Kind := FBVBS.ABI.X25519;
        Dispatch_Request.Allowed_Ops := FBVBS.ABI.IKS_Op_Key_Exchange or FBVBS.ABI.IKS_Op_Derive;
        Dispatch_Request.Key_Length := 32;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_IKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Key_Handle = 16#A001#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_IKS_Key_Exchange;
        Dispatch_Request.Caller_Sequence := 52;
        Dispatch_Request.Caller_Nonce := 16#CF#;
        Dispatch_Request.Key_Handle := 16#A001#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_IKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Key_Handle = 16#A002#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_IKS_Derive;
        Dispatch_Request.Caller_Sequence := 53;
        Dispatch_Request.Caller_Nonce := 16#D0#;
        Dispatch_Request.Key_Handle := 16#A001#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_IKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Key_Handle = 16#A003#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_SKS_Import_DEK;
        Dispatch_Request.Caller_Sequence := 54;
        Dispatch_Request.Caller_Nonce := 16#D1#;
        Dispatch_Request.Volume_Id := 1;
        Dispatch_Request.Key_Length := 32;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_SKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Dek_Handle = 16#B000#);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_SKS_Decrypt_Batch;
        Dispatch_Request.Caller_Sequence := 55;
        Dispatch_Request.Caller_Nonce := 16#D2#;
        Dispatch_Request.Dek_Handle := 16#B000#;
        Dispatch_Request.Descriptor_Count := 2;
        Dispatch_Request.Page_Aligned := True;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_SKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Completed_Count = 2);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_SKS_Encrypt_Batch;
        Dispatch_Request.Caller_Sequence := 56;
        Dispatch_Request.Caller_Nonce := 16#D3#;
        Dispatch_Request.Dek_Handle := 16#B000#;
        Dispatch_Request.Descriptor_Count := 2;
        Dispatch_Request.Page_Aligned := True;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_SKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Result.Completed_Count = 2);

        Dispatch_Request := (others => <>);
        Dispatch_Request.Call_Id := FBVBS.ABI.Call_SKS_Destroy_DEK;
        Dispatch_Request.Caller_Sequence := 57;
        Dispatch_Request.Caller_Nonce := 16#D4#;
        Dispatch_Request.Dek_Handle := 16#B000#;
        FBVBS.Hypercall_Dispatcher.Dispatch
          (Dispatch_Tracker,
           Dispatch_State,
           Dispatch_SKS_Caller,
           Dispatch_Target,
           FBVBS_Host_Profile,
           Dispatch_Caps,
           Dispatch_Domain,
           Dispatch_Artifact,
           Dispatch_Log,
           Dispatch_Verify,
           Dispatch_Manifest,
           Dispatch_VCPU,
           Dispatch_Memory_Object,
           Dispatch_Next_Object_Id,
           Dispatch_Next_Partition_Id,
           Dispatch_Target_Set_State,
           Dispatch_Key_State,
           Dispatch_Dek_State,
           Dispatch_Next_Target_Set_Id,
           Dispatch_Next_Key_Handle,
           Dispatch_Next_Dek_Handle,
           Dispatch_Request,
           Dispatch_Result);
        pragma Assert (Dispatch_Result.Hypercall_Status = FBVBS.ABI.OK);
        pragma Assert (Dispatch_Log.Max_Readable_Sequence = 57);
      end;

      declare
         Lifecycle_Tracker  : FBVBS.ABI.Command_Tracker_Record;
         Lifecycle_State    : FBVBS.ABI.Command_State := FBVBS.ABI.Command_Ready;
         Lifecycle_Caller   : FBVBS.ABI.Partition_Descriptor := Host_Partition;
         Lifecycle_Target   : FBVBS.ABI.Partition_Descriptor;
         Reject_Target      : FBVBS.ABI.Partition_Descriptor;
         Fault_Target       : FBVBS.ABI.Partition_Descriptor;
         Lifecycle_Log      : FBVBS.ABI.Log_State_Record;
         Lifecycle_Caps     : FBVBS.ABI.Platform_Capabilities :=
           (Has_HLAT => True, Has_IOMMU => True);
         Lifecycle_Domain   : FBVBS.ABI.IOMMU_Domain_Record :=
           (In_Use                => True,
            Domain_Id             => 16#7700#,
            Owner_Partition_Id    => 1,
            Attached_Device_Count => 0);
         Lifecycle_Artifact : FBVBS.ABI.Artifact_Catalog_Entry_Record :=
           (Object_Id => 16#8800#,
            Object_Kind => FBVBS.ABI.Artifact_Module,
            Related_Index => 4);
         Lifecycle_Verify   : FBVBS.ABI.Verification_Record;
         Lifecycle_Manifest : FBVBS.ABI.Manifest_Set_Record;
         Lifecycle_VCPU     : FBVBS.ABI.VCPU_Record;
         Lifecycle_Memory   : FBVBS.ABI.Memory_Object_Record;
         Lifecycle_Next_Object_Id : FBVBS.ABI.Handle := 16#C000#;
         Lifecycle_Next_Partition_Id : FBVBS.ABI.Handle := 16#5100#;
         Lifecycle_Target_Set_State : FBVBS.ABI.Target_Set_Record;
         Lifecycle_Key_State : FBVBS.ABI.Key_Record;
         Lifecycle_Dek_State : FBVBS.ABI.Dek_Record;
         Lifecycle_Next_Target_Set_Id : FBVBS.ABI.Handle := 16#D000#;
         Lifecycle_Next_Key_Handle : FBVBS.ABI.Handle := 16#D100#;
         Lifecycle_Next_Dek_Handle : FBVBS.ABI.Handle := 16#D200#;
         Lifecycle_Request  : FBVBS.ABI.Dispatch_Request_Record;
         Lifecycle_Result   : FBVBS.ABI.Dispatch_Result_Record;
      begin
         FBVBS.Commands.Initialize (Lifecycle_Tracker);
         FBVBS.Logging.Initialize (Lifecycle_Log, 3, 5, Status);
         pragma Assert (Status = FBVBS.ABI.OK);
         FBVBS.KCI.Initialize (Lifecycle_Verify);
         FBVBS.UVS.Initialize (Lifecycle_Manifest);
         FBVBS.VMX.Initialize (Lifecycle_VCPU);
         FBVBS.Memory.Initialize_Object (Lifecycle_Memory);
         FBVBS.KSI.Initialize (Lifecycle_Target_Set_State);
         FBVBS.IKS.Initialize (Lifecycle_Key_State);
         FBVBS.SKS.Initialize (Lifecycle_Dek_State);
         FBVBS.Partitions.Initialize (Lifecycle_Target);
         FBVBS.Partitions.Initialize (Reject_Target);
         FBVBS.Partitions.Initialize (Fault_Target);

         Lifecycle_Request := (others => <>);
         Lifecycle_Request.Call_Id := FBVBS.ABI.Call_Partition_Create;
         Lifecycle_Request.Caller_Sequence := 1;
         Lifecycle_Request.Caller_Nonce := 16#E1#;
         Lifecycle_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
         Lifecycle_Request.Requested_Kind := FBVBS.ABI.Partition_Trusted_Service;
         Lifecycle_Request.Requested_VCPU_Count := 2;
         Lifecycle_Request.Requested_Memory_Limit := 16384;
         Lifecycle_Request.Requested_Capability_Mask := FBVBS.ABI.Capability_Memory_Map;
         Lifecycle_Request.Image_Object_Id := 16#1234#;
         FBVBS.Hypercall_Dispatcher.Dispatch
           (Lifecycle_Tracker,
            Lifecycle_State,
            Lifecycle_Caller,
            Lifecycle_Target,
            FBVBS_Host_Profile,
            Lifecycle_Caps,
            Lifecycle_Domain,
            Lifecycle_Artifact,
            Lifecycle_Log,
            Lifecycle_Verify,
            Lifecycle_Manifest,
            Lifecycle_VCPU,
            Lifecycle_Memory,
            Lifecycle_Next_Object_Id,
            Lifecycle_Next_Partition_Id,
            Lifecycle_Target_Set_State,
            Lifecycle_Key_State,
            Lifecycle_Dek_State,
            Lifecycle_Next_Target_Set_Id,
            Lifecycle_Next_Key_Handle,
            Lifecycle_Next_Dek_Handle,
            Lifecycle_Request,
            Lifecycle_Result);
         pragma Assert (Lifecycle_Result.Hypercall_Status = FBVBS.ABI.OK);
         pragma Assert (Lifecycle_Result.Partition_Id = 16#5100#);
         pragma Assert (Lifecycle_Target.Kind = FBVBS.ABI.Partition_Trusted_Service);
         pragma Assert (Lifecycle_Target.State = FBVBS.ABI.Created);
         pragma Assert (Lifecycle_Target.Memory_Limit_Bytes = 16384);
         pragma Assert (Lifecycle_Next_Partition_Id = 16#5101#);

         Lifecycle_Request := (others => <>);
         Lifecycle_Request.Call_Id := FBVBS.ABI.Call_Partition_Create;
         Lifecycle_Request.Caller_Sequence := 2;
         Lifecycle_Request.Caller_Nonce := 16#E2#;
         Lifecycle_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
         Lifecycle_Request.Requested_Kind := FBVBS.ABI.Partition_Guest_VM;
         Lifecycle_Request.Requested_VCPU_Count := 1;
         Lifecycle_Request.Requested_Memory_Limit := 4096;
         Lifecycle_Request.Requested_Capability_Mask := 0;
         Lifecycle_Request.Image_Object_Id := 16#2345#;
         FBVBS.Hypercall_Dispatcher.Dispatch
           (Lifecycle_Tracker,
            Lifecycle_State,
            Lifecycle_Caller,
            Reject_Target,
            FBVBS_Host_Profile,
            Lifecycle_Caps,
            Lifecycle_Domain,
            Lifecycle_Artifact,
            Lifecycle_Log,
            Lifecycle_Verify,
            Lifecycle_Manifest,
            Lifecycle_VCPU,
            Lifecycle_Memory,
            Lifecycle_Next_Object_Id,
            Lifecycle_Next_Partition_Id,
            Lifecycle_Target_Set_State,
            Lifecycle_Key_State,
            Lifecycle_Dek_State,
            Lifecycle_Next_Target_Set_Id,
            Lifecycle_Next_Key_Handle,
            Lifecycle_Next_Dek_Handle,
            Lifecycle_Request,
            Lifecycle_Result);
         pragma Assert (Lifecycle_Result.Hypercall_Status = FBVBS.ABI.Invalid_Parameter);
         pragma Assert (not Reject_Target.In_Use);

         Lifecycle_Request := (others => <>);
         Lifecycle_Request.Call_Id := FBVBS.ABI.Call_Partition_Destroy;
         Lifecycle_Request.Caller_Sequence := 3;
         Lifecycle_Request.Caller_Nonce := 16#E3#;
         Lifecycle_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
         FBVBS.Hypercall_Dispatcher.Dispatch
           (Lifecycle_Tracker,
            Lifecycle_State,
            Lifecycle_Caller,
            Lifecycle_Target,
            FBVBS_Host_Profile,
            Lifecycle_Caps,
            Lifecycle_Domain,
            Lifecycle_Artifact,
            Lifecycle_Log,
            Lifecycle_Verify,
            Lifecycle_Manifest,
            Lifecycle_VCPU,
            Lifecycle_Memory,
            Lifecycle_Next_Object_Id,
            Lifecycle_Next_Partition_Id,
            Lifecycle_Target_Set_State,
            Lifecycle_Key_State,
            Lifecycle_Dek_State,
            Lifecycle_Next_Target_Set_Id,
            Lifecycle_Next_Key_Handle,
            Lifecycle_Next_Dek_Handle,
            Lifecycle_Request,
            Lifecycle_Result);
         pragma Assert (Lifecycle_Result.Hypercall_Status = FBVBS.ABI.OK);
         pragma Assert (Lifecycle_Target.State = FBVBS.ABI.Destroyed);

         Lifecycle_Request := (others => <>);
         Lifecycle_Request.Call_Id := FBVBS.ABI.Call_Partition_Get_Status;
         Lifecycle_Request.Caller_Sequence := 4;
         Lifecycle_Request.Caller_Nonce := 16#E4#;
         Lifecycle_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
         FBVBS.Hypercall_Dispatcher.Dispatch
           (Lifecycle_Tracker,
            Lifecycle_State,
            Lifecycle_Caller,
            Lifecycle_Target,
            FBVBS_Host_Profile,
            Lifecycle_Caps,
            Lifecycle_Domain,
            Lifecycle_Artifact,
            Lifecycle_Log,
            Lifecycle_Verify,
            Lifecycle_Manifest,
            Lifecycle_VCPU,
            Lifecycle_Memory,
            Lifecycle_Next_Object_Id,
            Lifecycle_Next_Partition_Id,
            Lifecycle_Target_Set_State,
            Lifecycle_Key_State,
            Lifecycle_Dek_State,
            Lifecycle_Next_Target_Set_Id,
            Lifecycle_Next_Key_Handle,
            Lifecycle_Next_Dek_Handle,
            Lifecycle_Request,
            Lifecycle_Result);
         pragma Assert (Lifecycle_Result.Hypercall_Status = FBVBS.ABI.OK);
         pragma Assert (Lifecycle_Result.Partition_Status.State = FBVBS.ABI.Destroyed);

         FBVBS.Partitions.Create (Fault_Target, 16#5200#, Status);
         pragma Assert (Status = FBVBS.ABI.OK);
         FBVBS.Partitions.Measure (Fault_Target, True, Status);
         pragma Assert (Status = FBVBS.ABI.OK);
         FBVBS.Partitions.Load (Fault_Target, Status);
         pragma Assert (Status = FBVBS.ABI.OK);
         FBVBS.Partitions.Start (Fault_Target, Status);
         pragma Assert (Status = FBVBS.ABI.OK);
         FBVBS.Partitions.Fault
           (Fault_Target,
            FBVBS.ABI.Fault_Code_Partition_Internal,
            FBVBS.ABI.Source_Component_Microhypervisor,
            16#AA55#,
            16#55AA#,
            Status);
         pragma Assert (Status = FBVBS.ABI.OK);

         Lifecycle_Request := (others => <>);
         Lifecycle_Request.Call_Id := FBVBS.ABI.Call_Partition_Get_Fault_Info;
         Lifecycle_Request.Caller_Sequence := 5;
         Lifecycle_Request.Caller_Nonce := 16#E5#;
         Lifecycle_Request.Observed_RIP := FBVBS.ABI.Primary_Callsite (FBVBS_Host_Profile);
         FBVBS.Hypercall_Dispatcher.Dispatch
           (Lifecycle_Tracker,
            Lifecycle_State,
            Lifecycle_Caller,
            Fault_Target,
            FBVBS_Host_Profile,
            Lifecycle_Caps,
            Lifecycle_Domain,
            Lifecycle_Artifact,
            Lifecycle_Log,
            Lifecycle_Verify,
            Lifecycle_Manifest,
            Lifecycle_VCPU,
            Lifecycle_Memory,
            Lifecycle_Next_Object_Id,
            Lifecycle_Next_Partition_Id,
            Lifecycle_Target_Set_State,
            Lifecycle_Key_State,
            Lifecycle_Dek_State,
            Lifecycle_Next_Target_Set_Id,
            Lifecycle_Next_Key_Handle,
            Lifecycle_Next_Dek_Handle,
            Lifecycle_Request,
            Lifecycle_Result);
         pragma Assert (Lifecycle_Result.Hypercall_Status = FBVBS.ABI.OK);
         pragma Assert (Lifecycle_Result.Fault_Info.Fault_Code = FBVBS.ABI.Fault_Code_Partition_Internal);
         pragma Assert (Lifecycle_Result.Fault_Info.Source_Component = FBVBS.ABI.Source_Component_Microhypervisor);
         pragma Assert (Lifecycle_Result.Fault_Info.Fault_Detail0 = 16#AA55#);
         pragma Assert (Lifecycle_Result.Fault_Info.Fault_Detail1 = 16#55AA#);
      end;

      declare
         Memory_Partition : FBVBS.ABI.Partition_Descriptor :=
          (In_Use             => True,
           Partition_Id       => 16#55#,
           Kind               => FBVBS.ABI.Partition_Guest_VM,
           State              => FBVBS.ABI.Created,
           Measurement_Epoch  => 0,
           Service_Kind       => FBVBS.ABI.Service_None,
           Memory_Limit_Bytes => 8192,
           Capability_Mask    => FBVBS.ABI.Capability_Memory_Map or FBVBS.ABI.Capability_Memory_Set_Permission,
           Mapped_Bytes       => 0,
           Last_Fault_Code  => 0,
           Last_Source_Component => 0,
           Last_Fault_Detail0 => 0,
           Last_Fault_Detail1 => 0);
        Memory_Object    : FBVBS.ABI.Memory_Object_Record;
        Next_Object_Id   : FBVBS.ABI.Handle := 16#9000#;
     begin
        FBVBS.Memory.Initialize_Object (Memory_Object);
        FBVBS.Memory.Allocate_Object
          (Object         => Memory_Object,
           Next_Object_Id => Next_Object_Id,
           Size           => 4096,
           Object_Flags   => FBVBS.ABI.Memory_Object_Flag_Guest_Memory,
           Status         => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        pragma Assert (Memory_Object.Memory_Object_Id = 16#9000#);

         FBVBS.Memory.Map_Object
          (Partition              => Memory_Partition,
           Object                 => Memory_Object,
           Memory_Object_Id       => 16#9000#,
           Guest_Physical_Address => 16#4000#,
           Size                   => 4096,
           Permissions            => FBVBS.ABI.Memory_Permission_Read or FBVBS.ABI.Memory_Permission_Execute,
           Status                 => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        pragma Assert (Memory_Partition.Mapped_Bytes = 4096);
        pragma Assert (Memory_Object.Map_Count = 1);

        FBVBS.Memory.Release_Object (Memory_Object, Status);
        pragma Assert (Status = FBVBS.ABI.Resource_Busy);

        FBVBS.Memory.Set_Permissions
          (Partition   => Memory_Partition,
           Permissions => FBVBS.ABI.Memory_Permission_Read
             or FBVBS.ABI.Memory_Permission_Write
             or FBVBS.ABI.Memory_Permission_Execute,
           Status      => Status);
        pragma Assert (Status = FBVBS.ABI.Invalid_Parameter);

        FBVBS.Memory.Unmap_Object
          (Partition => Memory_Partition,
           Object    => Memory_Object,
           Size      => 4096,
           Status    => Status);
        pragma Assert (Status = FBVBS.ABI.OK);
        pragma Assert (Memory_Partition.Mapped_Bytes = 0);

        FBVBS.Memory.Release_Object (Memory_Object, Status);
        pragma Assert (Status = FBVBS.ABI.OK);
     end;

     Guest_VM :=
       (In_Use            => True,
        Partition_Id      => 2,
        Kind              => FBVBS.ABI.Partition_Guest_VM,
        State             => FBVBS.ABI.Runnable,
        Measurement_Epoch => 0,
        Service_Kind      => FBVBS.ABI.Service_None,
        Memory_Limit_Bytes => 0,
        Capability_Mask    => 0,
        Mapped_Bytes       => 0,
           Last_Fault_Code  => 0,
           Last_Source_Component => 0,
           Last_Fault_Detail0 => 0,
           Last_Fault_Detail1 => 0);
    FBVBS.Partitions.Refresh_VM_State
      (Guest_VM,
       Any_Running             => True,
       Any_Runnable_Or_Blocked => True,
       Any_Faulted             => False,
       Status                  => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    pragma Assert (Guest_VM.State = FBVBS.ABI.Running);
    FBVBS.Partitions.Refresh_VM_State
      (Guest_VM,
       Any_Running             => False,
       Any_Runnable_Or_Blocked => True,
       Any_Faulted             => False,
       Status                  => Status);
    pragma Assert (Status = FBVBS.ABI.OK);
    pragma Assert (Guest_VM.State = FBVBS.ABI.Runnable);

    FBVBS.VMX.Initialize (VCPU);
    FBVBS.VMX.Start (VCPU);
    pragma Assert (VCPU.State = FBVBS.ABI.VCPU_Runnable);
     FBVBS.VMX.Inject_Interrupt (VCPU, 32, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_External_Interrupt);
     pragma Assert (Run_Result.Interrupt_Vector = 32);
     pragma Assert (VCPU.Interrupt_Pending = False);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 3);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 8);

     VCPU.RSP := 16#1234#;
     VCPU.RFlags := 1;
     VCPU.RIP := FBVBS.ABI.Synthetic_Exit_RIP_PIO;
     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_PIO);
     pragma Assert (Run_Result.Port = 16#1234#);
     pragma Assert (Run_Result.Access_Size = 4);
     pragma Assert (Run_Result.Is_Write);
     pragma Assert (Run_Result.Value = 1);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 1);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 8);

     VCPU.RSP := 16#2000#;
     VCPU.RFlags := 0;
     VCPU.RIP := FBVBS.ABI.Synthetic_Exit_RIP_MMIO;
     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_MMIO);
     pragma Assert (Run_Result.Guest_Physical_Address = 16#2000#);
     pragma Assert (Run_Result.Access_Size = 8);
     pragma Assert (not Run_Result.Is_Write);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 2);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 16);

     VCPU.CR0 := 0;
     VCPU.RIP := 0;
     FBVBS.VMX.Run (VCPU, True, 16#1#, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_CR_Access);
     pragma Assert (Run_Result.CR_Number = 0);
     pragma Assert (Run_Result.Value = 0);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 5);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 16);
     pragma Assert (FBVBS.VM_Exit_Encoding.CR_Access_Type = 1);

     FBVBS.VMX.Run (VCPU, True, 0, 0, 16#C000_0080#, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_MSR_Access);
     pragma Assert (Run_Result.MSR_Address = 16#C000_0080#);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 6);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 16);
     pragma Assert (FBVBS.VM_Exit_Encoding.MSR_Access_Type = 1);

     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 0, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_EPT_Violation);
     pragma Assert (Run_Result.Guest_Physical_Address = 0);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 4);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 16);
     pragma Assert (FBVBS.VM_Exit_Encoding.EPT_Access_Type = 16#4#);

     VCPU.RIP := FBVBS.ABI.Synthetic_Exit_RIP_Shutdown;
     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_Shutdown);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 8);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 0);

     VCPU.RIP := FBVBS.ABI.Synthetic_Exit_RIP_Fault;
     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_Unclassified_Fault);
     pragma Assert (Run_Result.Fault_Code = FBVBS.ABI.Fault_Code_VM_Exit_Unclassified);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 9);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 24);

     FBVBS.Partitions.Refresh_VM_State
       (Guest_VM,
        Any_Running             => False,
        Any_Runnable_Or_Blocked => False,
        Any_Faulted             => True,
        Status                  => Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Guest_VM.State = FBVBS.ABI.Faulted);
     FBVBS.VMX.Recover (VCPU, Status);
     pragma Assert (Status = FBVBS.ABI.OK);

     VCPU.RIP := 0;
     FBVBS.VMX.Run (VCPU, True, 0, 0, 0, 4096, 0, Run_Result, Status);
     pragma Assert (Status = FBVBS.ABI.OK);
     pragma Assert (Run_Result.Exit_Reason = FBVBS.ABI.Exit_Halt);
     pragma Assert (VCPU.State = FBVBS.ABI.VCPU_Blocked);
     pragma Assert (FBVBS.VM_Exit_Encoding.Exit_Code (Run_Result.Exit_Reason) = 7);
     pragma Assert (FBVBS.VM_Exit_Encoding.Payload_Length (Run_Result.Exit_Reason) = 0);
 end FBVBS_Hypervisor_Main;
