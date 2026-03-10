with FBVBS.ABI;
with FBVBS.Commands;
with FBVBS.Diagnostics;
with FBVBS.IKS;
with FBVBS.KCI;
with FBVBS.KSI;
with FBVBS.Logging;
with FBVBS.Memory;
with FBVBS.Partitions;
with FBVBS.SKS;
with FBVBS.UVS;
with FBVBS.VM_Exit_Encoding;
with FBVBS.VMX;

package body FBVBS.Hypercall_Dispatcher
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Partition_Kind;
   use type FBVBS.ABI.Partition_State;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.VCPU_State;

   function Is_VM_Call (Call_Id : FBVBS.ABI.U32) return Boolean is
     (Call_Id = FBVBS.ABI.Call_VM_Create
      or else Call_Id = FBVBS.ABI.Call_VM_Destroy
      or else Call_Id = FBVBS.ABI.Call_VM_Run
      or else Call_Id = FBVBS.ABI.Call_VM_Set_Register
      or else Call_Id = FBVBS.ABI.Call_VM_Get_Register
      or else Call_Id = FBVBS.ABI.Call_VM_Map_Memory
      or else Call_Id = FBVBS.ABI.Call_VM_Inject_Interrupt
      or else Call_Id = FBVBS.ABI.Call_VM_Assign_Device
      or else Call_Id = FBVBS.ABI.Call_VM_Release_Device
      or else Call_Id = FBVBS.ABI.Call_VM_Get_VCPU_Status);

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
      Result           : out FBVBS.ABI.Dispatch_Result_Record)
   is
      Status     : FBVBS.ABI.Status_Code;
      Log_Status : FBVBS.ABI.Status_Code;
   begin
      Result :=
        (Hypercall_Status     => FBVBS.ABI.OK,
         Actual_Output_Length => 0,
         Revoked              => False,
         Failure_Bitmap       => 0,
         Partition_Id         => 0,
         Memory_Object_Id     => 0,
         Ucred_Object_Id      => 0,
         Shared_Object_Id     => 0,
         Target_Set_Id        => 0,
         Key_Handle           => 0,
         Dek_Handle           => 0,
         Register_Value       => 0,
         Verdict              => 0,
         Returned_Length      => 0,
         Completed_Count      => 0,
         Boot_Id_Hi           => 0,
         Boot_Id_Lo           => 0,
         Diag_Capabilities    => (Capability_Bitmap0 => 0, Capability_Bitmap1 => 0),
         Diag_Partition       => (Count        => 0,
                                  Partition_Id => 0,
                                  State        => FBVBS.ABI.Created,
                                  Kind         => FBVBS.ABI.Partition_None,
                                  Service_Kind => FBVBS.ABI.Service_None),
         Diag_Artifact        => (Count         => 0,
                                  Object_Id     => 0,
                                  Object_Kind   => FBVBS.ABI.Artifact_None,
                                  Related_Index => 0),
         Diag_Device          => (Count         => 0,
                                  Device_Id     => 0,
                                  Segment       => 0,
                                  Bus           => 0,
                                  Slot_Function => 0),
         Partition_Status     => (State => FBVBS.ABI.Created, Measurement_Epoch => 0),
         Audit_Mirror         => (Ring_GPA => 0, Ring_Size => 0, Record_Size => 0),
         Fault_Info           => (Fault_Code => 0,
                                  Source_Component => 0,
                                  Fault_Detail0 => 0,
                                  Fault_Detail1 => 0),
         VCPU_State_Value     => FBVBS.ABI.VCPU_Created,
         VM_Result            => (Exit_Reason            => FBVBS.ABI.No_Exit,
                                  Fault_Code             => 0,
                                  Detail0                => 0,
                                  Detail1                => 0,
                                  Interrupt_Vector       => 0,
                                  CR_Number              => 0,
                                  MSR_Address            => 0,
                                  Port                   => 0,
                                  Access_Size            => 0,
                                  Is_Write               => False,
                                  Value                  => 0,
                                  Guest_Physical_Address => 0));

      FBVBS.Commands.Begin_Dispatch
        (Tracker              => Tracker,
         State                => Command_State,
         Actual_Output_Length => Request.Actual_Output_Length,
         Caller_Sequence      => Request.Caller_Sequence,
         Caller_Nonce         => Request.Caller_Nonce,
         Status               => Status);

      if Status = FBVBS.ABI.OK and then Caller.Kind = FBVBS.ABI.Partition_FreeBSD_Host then
         declare
            Primary_Callsite   : FBVBS.ABI.U64 := FBVBS.ABI.Primary_Callsite (Host_Profile);
            Secondary_Callsite : FBVBS.ABI.U64 := FBVBS.ABI.Secondary_Callsite (Host_Profile);
            Required_Class     : FBVBS.ABI.Host_Caller_Class := Host_Profile.Caller_Class;
         begin
            if Is_VM_Call (Request.Call_Id) then
               Primary_Callsite := FBVBS.ABI.Host_Callsite_VMM_Primary;
               Secondary_Callsite := FBVBS.ABI.Host_Callsite_VMM_Secondary;
               Required_Class := FBVBS.ABI.Host_Caller_VMM;
            end if;

            FBVBS.Commands.Validate_Host_Callsite
              (Observed_RIP        => Request.Observed_RIP,
               Primary_Callsite    => Primary_Callsite,
               Secondary_Callsite  => Secondary_Callsite,
               Required_Class      => Required_Class,
               Status              => Status);
         end;
      end if;

      if Status = FBVBS.ABI.OK then
         case Request.Call_Id is
            when FBVBS.ABI.Call_UVS_Verify_Manifest_Set =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_UVS, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.UVS.Verify_Manifest_Set
                    (State                    => Manifest_State,
                     Verified_Manifest_Set_Id => Request.Verified_Manifest_Set_Id,
                     Manifest_Count           => Request.Manifest_Count,
                     Revoked_Object_Id        => Request.Revoked_Object_Id,
                     Signatures_Valid         => Request.Signatures_Valid,
                     Not_Revoked              => Request.Not_Revoked,
                     Generation_Valid         => Request.Generation_Valid,
                     Rollback_Free            => Request.Rollback_Free,
                     Dependencies_Satisfied   => Request.Dependencies_Satisfied,
                     Snapshot_Consistent      => Request.Snapshot_Consistent,
                     Freshness_Valid          => Request.Freshness_Valid,
                     Status                   => Status);
                  Result.Failure_Bitmap := Manifest_State.Failure_Bitmap;
                  Result.Actual_Output_Length := 4;
               end if;

            when FBVBS.ABI.Call_UVS_Verify_Artifact =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_UVS, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.UVS.Verify_Artifact
                    (State              => Manifest_State,
                     Artifact_Object_Id => Request.Artifact_Object_Id,
                     Manifest_Object_Id => Request.Manifest_Object_Id,
                     Tail_Zero          => Request.Tail_Zero,
                     Hash_Matches       => Request.Hash_Matches,
                     Status             => Status);
               end if;

            when FBVBS.ABI.Call_UVS_Check_Revocation =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_UVS, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.UVS.Check_Revocation
                    (State        => Manifest_State,
                     Object_Id    => Request.Object_Id,
                     Known_Object => Request.Known_Object,
                     Revoked      => Result.Revoked,
                     Status       => Status);
                  Result.Actual_Output_Length := 8;
               end if;

            when FBVBS.ABI.Call_Partition_Create =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Requested_Kind /= FBVBS.ABI.Partition_Trusted_Service then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     FBVBS.Partitions.Create_Trusted_Service
                       (Partition            => Target_Partition,
                        Partition_Id         => FBVBS.ABI.U64 (Next_Partition_Id),
                        Requested_VCPU_Count => Request.Requested_VCPU_Count,
                        Memory_Limit_Bytes   => Request.Requested_Memory_Limit,
                        Capability_Mask      => Request.Requested_Capability_Mask,
                        Image_Object_Id      => Request.Image_Object_Id,
                        Create_Flags         => Request.Create_Flags,
                        Status               => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Partition_Id := Next_Partition_Id;
                        Result.Actual_Output_Length := 8;
                        Next_Partition_Id := Next_Partition_Id + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_Partition_Destroy =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Destroy (Target_Partition, Status);
               end if;

            when FBVBS.ABI.Call_Partition_Get_Status =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Get_Status
                    (Partition => Target_Partition,
                     Result    => Result.Partition_Status,
                     Status    => Status);
                  if Status = FBVBS.ABI.OK then
                     Result.Actual_Output_Length := 16;
                   end if;
                end if;

            when FBVBS.ABI.Call_Partition_Get_Fault_Info =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Get_Fault_Info
                    (Partition => Target_Partition,
                     Result    => Result.Fault_Info,
                     Status    => Status);
                  if Status = FBVBS.ABI.OK then
                     Result.Actual_Output_Length := 24;
                  end if;
               end if;

            when FBVBS.ABI.Call_Partition_Quiesce =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Quiesce (Target_Partition, Status);
               end if;

            when FBVBS.ABI.Call_Partition_Resume =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Resume (Target_Partition, Status);
               end if;

            when FBVBS.ABI.Call_Partition_Measure =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Measure
                    (Partition        => Target_Partition,
                     Approval_Present => Request.Approval_Present,
                     Status           => Status);
               end if;

            when FBVBS.ABI.Call_Partition_Load_Image =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Load (Target_Partition, Status);
               end if;

            when FBVBS.ABI.Call_Partition_Start =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Start (Target_Partition, Status);
               end if;

            when FBVBS.ABI.Call_Partition_Recover =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Recover
                    (Partition => Target_Partition,
                     Has_Image => Request.Has_Image,
                     Status    => Status);
               end if;

            when FBVBS.ABI.Call_Memory_Allocate_Object =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Memory.Allocate_Object
                    (Object         => Memory_Object,
                     Next_Object_Id => Next_Object_Id,
                     Size           => Request.Size,
                     Object_Flags   => Request.Object_Flags,
                     Status         => Status);
                  Result.Memory_Object_Id := Memory_Object.Memory_Object_Id;
                  Result.Actual_Output_Length := 8;
               end if;

            when FBVBS.ABI.Call_Memory_Map =>
                FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
                if Status = FBVBS.ABI.OK then
                   FBVBS.Memory.Map_Object
                     (Partition              => Target_Partition,
                      Object                 => Memory_Object,
                      Memory_Object_Id       => Request.Memory_Object_Id,
                      Guest_Physical_Address => Request.Guest_Physical_Address,
                      Size                   => Request.Size,
                      Permissions            => Request.Permissions,
                      Status                 => Status);
                end if;

            when FBVBS.ABI.Call_VM_Create =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if not Caps.Has_HLAT then
                     Status := FBVBS.ABI.Not_Supported_On_Platform;
                  elsif Request.Requested_Kind /= FBVBS.ABI.Partition_None
                    and then Request.Requested_Kind /= FBVBS.ABI.Partition_Guest_VM
                  then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     FBVBS.Partitions.Create_VM
                       (Partition          => Target_Partition,
                        Partition_Id       => FBVBS.ABI.U64 (Next_Partition_Id),
                        VCPU_Count         => Request.Requested_VCPU_Count,
                        Memory_Limit_Bytes => Request.Requested_Memory_Limit,
                        VM_Flags           => Request.VM_Flags,
                        Status             => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Partition_Id := Next_Partition_Id;
                        Result.Actual_Output_Length := 8;
                        Next_Partition_Id := Next_Partition_Id + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_VM_Destroy =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Destroy_VM (Target_Partition, Status);
               end if;

            when FBVBS.ABI.Call_VM_Assign_Device =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Assign_Device
                    (Partition => Target_Partition,
                     Device_Id => Request.Device_Id,
                     Has_IOMMU => Caps.Has_IOMMU,
                     Status    => Status);
               end if;

            when FBVBS.ABI.Call_VM_Release_Device =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Partitions.Release_Device
                    (Partition => Target_Partition,
                     Device_Id => Request.Device_Id,
                     Status    => Status);
               end if;

            when FBVBS.ABI.Call_VM_Map_Memory =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Target_Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     FBVBS.Memory.Map_VM_Object
                       (Partition              => Target_Partition,
                        Object                 => Memory_Object,
                        Memory_Object_Id       => Request.Memory_Object_Id,
                        Guest_Physical_Address => Request.Guest_Physical_Address,
                        Size                   => Request.Size,
                        Permissions            => Request.Permissions,
                        Status                 => Status);
                  end if;
                end if;

            when FBVBS.ABI.Call_Memory_Unmap =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Memory.Unmap_Object
                    (Partition => Target_Partition,
                     Object    => Memory_Object,
                     Size      => Request.Size,
                     Status    => Status);
               end if;

            when FBVBS.ABI.Call_Memory_Set_Permission =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KCI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Memory.Set_Permissions
                    (Partition   => Target_Partition,
                     Permissions => Request.Permissions,
                     Status      => Status);
               end if;

            when FBVBS.ABI.Call_Memory_Register_Shared =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Memory.Register_Sharing
                    (Object            => Memory_Object,
                     Peer_Partition_Id => Request.Peer_Partition_Id,
                     Permissions       => Request.Permissions,
                     Shared_Object_Id  => Result.Shared_Object_Id,
                     Status            => Status);
                  if Status = FBVBS.ABI.OK then
                     Result.Actual_Output_Length := 8;
                  end if;
               end if;

            when FBVBS.ABI.Call_Memory_Release_Object =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Memory.Release_Object (Memory_Object, Status);
               end if;

            when FBVBS.ABI.Call_Memory_Unregister_Shared =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Memory.Unregister_Sharing (Memory_Object, Status);
               end if;

            when FBVBS.ABI.Call_KSI_Create_Target_Set =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
               if Status = FBVBS.ABI.OK then
                  if Next_Target_Set_Id = 0 then
                     Status := FBVBS.ABI.Resource_Exhausted;
                  else
                     FBVBS.KSI.Create_Target_Set
                       (State                   => Target_Set_State,
                        Target_Set_Id           => Next_Target_Set_Id,
                        First_Target_Object_Id  => Request.First_Target_Object_Id,
                        Second_Target_Object_Id => Request.Second_Target_Object_Id,
                        Target_Count            => Request.Target_Count,
                        Status                  => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Target_Set_Id := Target_Set_State.Target_Set_Id;
                        Result.Actual_Output_Length := 8;
                        Next_Target_Set_Id := Next_Target_Set_Id + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_KSI_Register_Tier_A =>
                FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
                if Status = FBVBS.ABI.OK then
                   FBVBS.KSI.Register_Target_Object
                     (State                  => Target_Set_State,
                      Object_Id              => Request.Object_Id,
                      Guest_Physical_Address => Request.Guest_Physical_Address,
                      Size                   => Request.Size,
                      Status                 => Status);
                end if;

            when FBVBS.ABI.Call_KSI_Register_Tier_B =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KSI.Register_Tier_B_Object
                    (State                  => Target_Set_State,
                     Object_Id              => Request.Object_Id,
                     Guest_Physical_Address => Request.Guest_Physical_Address,
                     Size                   => Request.Size,
                     Protection_Class       => Request.Protection_Class,
                     Status                 => Status);
                end if;

            when FBVBS.ABI.Call_KSI_Modify_Tier_B =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KSI.Modify_Tier_B_Object
                    (State        => Target_Set_State,
                     Object_Id    => Request.Object_Id,
                     Patch_Length => Request.Patch_Length,
                     Status       => Status);
               end if;

            when FBVBS.ABI.Call_KSI_Register_Pointer =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Target_Set_Id /= Target_Set_State.Target_Set_Id then
                     Status := FBVBS.ABI.Not_Found;
                  else
                     FBVBS.KSI.Register_Pointer
                       (State             => Target_Set_State,
                        Pointer_Object_Id => Request.Pointer_Object_Id,
                        Status            => Status);
                  end if;
               end if;

            when FBVBS.ABI.Call_KSI_Validate_Setuid =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
                if Status = FBVBS.ABI.OK then
                   FBVBS.KSI.Validate_Setuid
                    (State                  => Target_Set_State,
                     Operation_Class        => Request.Operation_Class,
                     Valid_Mask             => Request.Valid_Mask,
                     FSID                   => Request.FSID,
                     File_Id                => Request.File_Id,
                     Measured_Hash          => Request.Measured_Hash,
                     Requested_RUID         => Request.Requested_RUID,
                     Requested_EUID         => Request.Requested_EUID,
                     Requested_SUID         => Request.Requested_SUID,
                     Requested_RGID         => Request.Requested_RGID,
                     Requested_EGID         => Request.Requested_EGID,
                     Requested_SGID         => Request.Requested_SGID,
                     Caller_Ucred_Object_Id => Request.Caller_Ucred_Object_Id,
                     Jail_Context_Id        => Request.Jail_Context_Id,
                     MAC_Context_Id         => Request.MAC_Context_Id,
                     Status                 => Status);
                   if Status = FBVBS.ABI.OK then
                      Result.Verdict := 1;
                      Result.Actual_Output_Length := 8;
                   end if;
                end if;

            when FBVBS.ABI.Call_KSI_Allocate_Ucred =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KSI.Allocate_Ucred
                    (State                    => Target_Set_State,
                     Requested_UID            => Request.Requested_UID,
                     Requested_GID            => Request.Requested_GID,
                     Prison_Object_Id         => Request.Prison_Object_Id,
                     Template_Ucred_Object_Id => Request.Template_Ucred_Object_Id,
                     Ucred_Object_Id          => Result.Ucred_Object_Id,
                     Status                   => Status);
                  if Status = FBVBS.ABI.OK then
                     Result.Actual_Output_Length := 8;
                  end if;
               end if;

            when FBVBS.ABI.Call_KSI_Replace_Tier_B_Object =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
                if Status = FBVBS.ABI.OK then
                   if Request.Pointer_Object_Id /= 0
                    and then Request.Pointer_Object_Id /= Target_Set_State.Pointer_Object_Id
                  then
                     Status := FBVBS.ABI.Not_Found;
                  elsif Request.Object_Id /= 0
                    and then Request.Object_Id /= Target_Set_State.Active_Target_Object_Id
                  then
                     Status := FBVBS.ABI.Policy_Denied;
                  else
                     FBVBS.KSI.Replace_Tier_B_Object
                       (State         => Target_Set_State,
                        New_Object_Id => Request.New_Object_Id,
                        Status        => Status);
                   end if;
                end if;

            when FBVBS.ABI.Call_KSI_Unregister_Object =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KSI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KSI.Unregister_Object
                    (State     => Target_Set_State,
                     Object_Id => Request.Object_Id,
                     Status    => Status);
               end if;

            when FBVBS.ABI.Call_IKS_Import_Key =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_IKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Next_Key_Handle = 0 then
                     Status := FBVBS.ABI.Resource_Exhausted;
                  else
                     FBVBS.IKS.Import_Key
                       (State       => Key_State,
                        Key_Handle  => Next_Key_Handle,
                        Key_Kind    => Request.Requested_Key_Kind,
                        Allowed_Ops => Request.Allowed_Ops,
                        Key_Length  => Request.Key_Length,
                        Status      => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Key_Handle := Key_State.Key_Handle;
                        Result.Actual_Output_Length := 8;
                        Next_Key_Handle := Next_Key_Handle + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_IKS_Sign =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_IKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Key_Handle /= Key_State.Key_Handle then
                     Status := FBVBS.ABI.Not_Found;
                  else
                     FBVBS.IKS.Sign (Key_State, Status);
                     if Status = FBVBS.ABI.OK then
                        case Key_State.Key_Kind is
                           when FBVBS.ABI.Ed25519 | FBVBS.ABI.ECDSA_P256 =>
                              Result.Returned_Length := 64;
                           when FBVBS.ABI.RSA3072 =>
                              Result.Returned_Length := 384;
                           when others =>
                              Result.Returned_Length := 0;
                        end case;
                        Result.Actual_Output_Length := Result.Returned_Length + 8;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_IKS_Key_Exchange =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_IKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Key_Handle /= Key_State.Key_Handle then
                     Status := FBVBS.ABI.Not_Found;
                  elsif Next_Key_Handle = 0 then
                     Status := FBVBS.ABI.Resource_Exhausted;
                  else
                     FBVBS.IKS.Key_Exchange (Key_State, Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Key_Handle := Next_Key_Handle;
                        Result.Actual_Output_Length := 8;
                        Next_Key_Handle := Next_Key_Handle + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_IKS_Derive =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_IKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Key_Handle /= Key_State.Key_Handle then
                     Status := FBVBS.ABI.Not_Found;
                  elsif Next_Key_Handle = 0 then
                     Status := FBVBS.ABI.Resource_Exhausted;
                  else
                     FBVBS.IKS.Derive (Key_State, Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Key_Handle := Next_Key_Handle;
                        Result.Actual_Output_Length := 8;
                        Next_Key_Handle := Next_Key_Handle + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_IKS_Destroy_Key =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_IKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Key_Handle /= Key_State.Key_Handle then
                     Status := FBVBS.ABI.Not_Found;
                  else
                     FBVBS.IKS.Destroy_Key (Key_State, Status);
                  end if;
               end if;

            when FBVBS.ABI.Call_SKS_Import_DEK =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_SKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Next_Dek_Handle = 0 then
                     Status := FBVBS.ABI.Resource_Exhausted;
                  else
                     FBVBS.SKS.Import_DEK
                       (State      => Dek_State,
                        Dek_Handle => Next_Dek_Handle,
                        Volume_Id  => Request.Volume_Id,
                        Key_Length => Request.Key_Length,
                        Status     => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Dek_Handle := Dek_State.Dek_Handle;
                        Result.Actual_Output_Length := 8;
                        Next_Dek_Handle := Next_Dek_Handle + 1;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_SKS_Decrypt_Batch | FBVBS.ABI.Call_SKS_Encrypt_Batch =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_SKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Dek_Handle /= Dek_State.Dek_Handle then
                     Status := FBVBS.ABI.Not_Found;
                  else
                     FBVBS.SKS.Process_Batch
                       (State            => Dek_State,
                        Descriptor_Count => Request.Descriptor_Count,
                        Page_Aligned     => Request.Page_Aligned,
                        Status           => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Completed_Count := Request.Descriptor_Count;
                        Result.Actual_Output_Length := 8;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_SKS_Destroy_DEK =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_SKS, Status);
               if Status = FBVBS.ABI.OK then
                  if Request.Dek_Handle /= Dek_State.Dek_Handle then
                     Status := FBVBS.ABI.Not_Found;
                  else
                     FBVBS.SKS.Destroy_DEK (Dek_State, Status);
                  end if;
               end if;

            when FBVBS.ABI.Call_KCI_Verify_Module =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KCI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KCI.Verify_Module
                    (State              => Verify_State,
                     Module_Object_Id   => Request.Module_Object_Id,
                     Manifest_Object_Id => Request.Manifest_Object_Id,
                     Generation         => Request.Generation,
                     Status             => Status);
               end if;

            when FBVBS.ABI.Call_KCI_Set_WX =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KCI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KCI.Set_WX
                    (State            => Verify_State,
                     Module_Object_Id => Request.Module_Object_Id,
                     Writable         =>
                       (Request.Permissions and FBVBS.ABI.Memory_Permission_Write) /= 0,
                     Executable       =>
                       (Request.Permissions and FBVBS.ABI.Memory_Permission_Execute) /= 0,
                     Status           => Status);
               end if;

            when FBVBS.ABI.Call_KCI_Pin_CR =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KCI, Status);
               if Status = FBVBS.ABI.OK then
                  case Request.Pin_Register is
                     when 0 =>
                        FBVBS.KCI.Pin_CR0
                          (State    => Verify_State,
                           Pin_Mask => Request.Pin_Mask,
                           Status   => Status);
                     when 4 =>
                        FBVBS.KCI.Pin_CR4
                          (State    => Verify_State,
                           Pin_Mask => Request.Pin_Mask,
                           Status   => Status);
                     when others =>
                        Status := FBVBS.ABI.Invalid_Parameter;
                  end case;
               end if;

            when FBVBS.ABI.Call_KCI_Intercept_MSR =>
               FBVBS.Commands.Validate_Caller (Caller, False, FBVBS.ABI.Service_KCI, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.KCI.Intercept_MSR
                    (State       => Verify_State,
                     MSR_Address => Request.MSR_Address,
                     Enable      => Request.Enable,
                     Status      => Status);
               end if;

            when FBVBS.ABI.Call_VM_Inject_Interrupt =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Target_Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     FBVBS.VMX.Inject_Interrupt
                       (VCPU   => VCPU,
                        Vector => Request.Interrupt_Vector,
                        Status => Status);
                  end if;
               end if;

            when FBVBS.ABI.Call_VM_Run =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Target_Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  elsif Target_Partition.State /= FBVBS.ABI.Runnable then
                     Status := FBVBS.ABI.Invalid_State;
                  else
                     FBVBS.VMX.Run
                       (VCPU             => VCPU,
                        Has_HLAT         => Caps.Has_HLAT,
                        Pinned_CR0_Mask  => Verify_State.Pinned_CR0_Mask,
                        Pinned_CR4_Mask  => Verify_State.Pinned_CR4_Mask,
                        Intercepted_MSRs =>
                          (if Verify_State.Intercepted_MSR_Count = 0 then 0
                           else FBVBS.ABI.KCI_MSR_EFER),
                        Mapped_Bytes     => Request.Mapped_Bytes,
                        VCPU_Id          => Request.VCPU_Id,
                        Result           => Result.VM_Result,
                        Status           => Status);
                     if Status = FBVBS.ABI.OK then
                        FBVBS.Partitions.Refresh_VM_State
                          (Partition               => Target_Partition,
                           Any_Running             =>
                             VCPU.State = FBVBS.ABI.VCPU_Running,
                           Any_Runnable_Or_Blocked =>
                             VCPU.State = FBVBS.ABI.VCPU_Runnable
                             or else VCPU.State = FBVBS.ABI.VCPU_Blocked,
                           Any_Faulted             =>
                             VCPU.State = FBVBS.ABI.VCPU_Faulted,
                           Status                  => Status);
                        Status := FBVBS.ABI.OK;
                     end if;
                     Result.Actual_Output_Length :=
                       FBVBS.VM_Exit_Encoding.Payload_Length (Result.VM_Result.Exit_Reason);
                  end if;
               end if;

            when FBVBS.ABI.Call_VM_Set_Register =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Target_Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     FBVBS.VMX.Set_Register
                       (VCPU        => VCPU,
                        Register_Id => Request.Register_Id,
                        Value       => Request.Register_Value,
                        Status      => Status);
                  end if;
               end if;

            when FBVBS.ABI.Call_VM_Get_Register =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Target_Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     FBVBS.VMX.Get_Register
                       (VCPU        => VCPU,
                        Register_Id => Request.Register_Id,
                        Value       => Result.Register_Value,
                        Status      => Status);
                     if Status = FBVBS.ABI.OK then
                        Result.Actual_Output_Length := 8;
                     end if;
                  end if;
               end if;

            when FBVBS.ABI.Call_VM_Get_VCPU_Status =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  if Target_Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
                     Status := FBVBS.ABI.Invalid_Parameter;
                  else
                     Result.VCPU_State_Value := VCPU.State;
                     Result.Actual_Output_Length := 8;
                  end if;
               end if;

            when FBVBS.ABI.Call_Audit_Get_Mirror_Info =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Logging.Get_Mirror_Info
                    (State  => Log_State,
                     Result => Result.Audit_Mirror,
                     Status => Status);
                  if Status = FBVBS.ABI.OK then
                     Result.Actual_Output_Length := 16;
                  end if;
               end if;

            when FBVBS.ABI.Call_Audit_Get_Boot_Id =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  Result.Boot_Id_Hi := Log_State.Boot_Id_Hi;
                  Result.Boot_Id_Lo := Log_State.Boot_Id_Lo;
                  Result.Actual_Output_Length := 16;
               end if;

            when FBVBS.ABI.Call_Diag_Get_Capabilities =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Diagnostics.Get_Capabilities (Caps, Result.Diag_Capabilities);
                  Result.Actual_Output_Length := 16;
               end if;

            when FBVBS.ABI.Call_Diag_Get_Partition_List =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Diagnostics.Describe_Partition (Target_Partition, Result.Diag_Partition);
                  Result.Actual_Output_Length := 16;
               end if;

            when FBVBS.ABI.Call_Diag_Get_Artifact_List =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Diagnostics.Describe_Artifact (Artifact, Result.Diag_Artifact);
                  Result.Actual_Output_Length := 16;
               end if;

            when FBVBS.ABI.Call_Diag_Get_Device_List =>
               FBVBS.Commands.Validate_Caller (Caller, True, FBVBS.ABI.Service_None, Status);
               if Status = FBVBS.ABI.OK then
                  FBVBS.Diagnostics.Describe_Device
                    (Device_Id     => Request.Device_Id,
                     Segment       => Request.Device_Segment,
                     Bus           => Request.Device_Bus,
                     Slot_Function => Request.Device_Slot_Function,
                     Domain        => Domain,
                     Result        => Result.Diag_Device);
                  Result.Actual_Output_Length := 16;
               end if;

            when others =>
               Status := FBVBS.ABI.Invalid_Parameter;
         end case;

         Result.Hypercall_Status := Status;
         FBVBS.Commands.Finish_Dispatch
           (State                => Command_State,
            Hypercall_Status     => Status,
            Actual_Output_Length => Result.Actual_Output_Length);

         if Log_State.Initialized then
            FBVBS.Logging.Append_Record
              (State          => Log_State,
               Payload_Length => 1,
               Status         => Log_Status);
         end if;
      else
         Result.Hypercall_Status := Status;
      end if;
   end Dispatch;
end FBVBS.Hypercall_Dispatcher;
