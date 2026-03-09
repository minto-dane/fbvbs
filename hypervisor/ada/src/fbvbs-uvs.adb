with FBVBS.ABI;

package body FBVBS.UVS
  with SPARK_Mode
is
   use type FBVBS.ABI.U32;

   function Status_From_Failure (Failure_Bitmap : FBVBS.ABI.U32) return FBVBS.ABI.Status_Code is
   begin
      if (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Signature) /= 0 then
         return FBVBS.ABI.Signature_Invalid;
      elsif (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Revocation) /= 0 then
         return FBVBS.ABI.Revoked;
      elsif (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Generation) /= 0 then
         return FBVBS.ABI.Generation_Mismatch;
      elsif (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Rollback) /= 0 then
         return FBVBS.ABI.Rollback_Detected;
      elsif (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Dependency) /= 0 then
         return FBVBS.ABI.Dependency_Unsatisfied;
      elsif (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Snapshot) /= 0 then
         return FBVBS.ABI.Snapshot_Inconsistent;
      elsif (Failure_Bitmap and FBVBS.ABI.UVS_Failure_Freshness) /= 0 then
         return FBVBS.ABI.Freshness_Failed;
      else
         return FBVBS.ABI.OK;
      end if;
   end Status_From_Failure;

    procedure Initialize (State : out FBVBS.ABI.Manifest_Set_Record) is
   begin
      State :=
        (In_Use                   => False,
         Verified_Manifest_Set_Id => 0,
         Verdict                  => 0,
         Manifest_Count           => 0,
         Failure_Bitmap           => 0,
         Approved_Artifact_Object_Id => 0,
         Approved_Manifest_Object_Id => 0,
         Revoked_Object_Id        => 0);
   end Initialize;

    procedure Verify_Manifest_Set
      (State                    : in out FBVBS.ABI.Manifest_Set_Record;
       Verified_Manifest_Set_Id : FBVBS.ABI.Handle;
       Manifest_Count           : FBVBS.ABI.U32;
       Revoked_Object_Id        : FBVBS.ABI.Handle;
       Signatures_Valid         : Boolean;
       Not_Revoked              : Boolean;
       Generation_Valid         : Boolean;
       Rollback_Free            : Boolean;
       Dependencies_Satisfied   : Boolean;
       Snapshot_Consistent      : Boolean;
       Freshness_Valid          : Boolean;
       Status                   : out FBVBS.ABI.Status_Code)
    is
       Failure_Bitmap : FBVBS.ABI.U32 := 0;
    begin
       if State.In_Use then
          Status := FBVBS.ABI.Invalid_State;
       elsif Verified_Manifest_Set_Id = 0 or else Manifest_Count = 0 then
          Status := FBVBS.ABI.Invalid_Parameter;
       else
          if not Signatures_Valid then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Signature;
          end if;
          if not Not_Revoked then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Revocation;
          end if;
          if not Generation_Valid then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Generation;
          end if;
          if not Rollback_Free then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Rollback;
          end if;
          if not Dependencies_Satisfied then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Dependency;
          end if;
          if not Snapshot_Consistent then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Snapshot;
          end if;
          if not Freshness_Valid then
             Failure_Bitmap := Failure_Bitmap or FBVBS.ABI.UVS_Failure_Freshness;
          end if;

          State.In_Use := Failure_Bitmap = 0;
          State.Verified_Manifest_Set_Id := (if Failure_Bitmap = 0 then Verified_Manifest_Set_Id else 0);
          State.Manifest_Count := Manifest_Count;
          State.Verdict := (if Failure_Bitmap = 0 then 1 else 0);
          State.Failure_Bitmap := Failure_Bitmap;
          State.Revoked_Object_Id := (if not Not_Revoked then Revoked_Object_Id else 0);
          Status := Status_From_Failure (Failure_Bitmap);
       end if;
    end Verify_Manifest_Set;

    procedure Verify_Artifact
      (State              : in out FBVBS.ABI.Manifest_Set_Record;
       Artifact_Object_Id : FBVBS.ABI.Handle;
       Manifest_Object_Id : FBVBS.ABI.Handle;
       Tail_Zero          : Boolean;
       Hash_Matches       : Boolean;
       Status             : out FBVBS.ABI.Status_Code)
    is
    begin
       if not State.In_Use then
          Status := FBVBS.ABI.Not_Found;
       elsif Artifact_Object_Id = 0 or else Manifest_Object_Id = 0 then
          Status := FBVBS.ABI.Invalid_Parameter;
       elsif not Tail_Zero then
          Status := FBVBS.ABI.Invalid_Parameter;
       elsif not Hash_Matches then
          Status := FBVBS.ABI.Dependency_Unsatisfied;
       else
          State.Approved_Artifact_Object_Id := Artifact_Object_Id;
          State.Approved_Manifest_Object_Id := Manifest_Object_Id;
          Status := FBVBS.ABI.OK;
       end if;
    end Verify_Artifact;

    procedure Require_Artifact_Approval
      (State              : FBVBS.ABI.Manifest_Set_Record;
       Artifact_Object_Id : FBVBS.ABI.Handle;
       Manifest_Object_Id : FBVBS.ABI.Handle;
       Status             : out FBVBS.ABI.Status_Code)
    is
    begin
       if not State.In_Use then
          Status := FBVBS.ABI.Not_Found;
       elsif State.Approved_Artifact_Object_Id /= Artifact_Object_Id or else
         State.Approved_Manifest_Object_Id /= Manifest_Object_Id
       then
          Status := FBVBS.ABI.Signature_Invalid;
       else
          Status := FBVBS.ABI.OK;
       end if;
    end Require_Artifact_Approval;

    procedure Check_Revocation
      (State        : in out FBVBS.ABI.Manifest_Set_Record;
       Object_Id    : FBVBS.ABI.Handle;
       Known_Object : Boolean;
       Revoked      : out Boolean;
       Status       : out FBVBS.ABI.Status_Code)
    is
    begin
       Revoked := False;
       if not State.In_Use then
          Status := FBVBS.ABI.Not_Found;
       elsif not Known_Object then
          Status := FBVBS.ABI.Not_Found;
       else
          Revoked := State.Revoked_Object_Id = Object_Id and then Object_Id /= 0;
          Status := FBVBS.ABI.OK;
       end if;
    end Check_Revocation;
end FBVBS.UVS;
