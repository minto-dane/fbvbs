with FBVBS.ABI;

package FBVBS.UVS
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.Manifest_Set_Record;

   procedure Initialize (State : out FBVBS.ABI.Manifest_Set_Record)
     with Post => not State.In_Use;

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
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
              State.In_Use
              and then State.Verified_Manifest_Set_Id = Verified_Manifest_Set_Id
              and then State.Manifest_Count = Manifest_Count
              and then State.Verdict = 1
              and then State.Failure_Bitmap = 0
           elsif Status = FBVBS.ABI.Revoked then
              State.Revoked_Object_Id = Revoked_Object_Id
              and then State.Verified_Manifest_Set_Id = 0
              and then State.Verdict = 0
           else
              True);

    procedure Verify_Artifact
      (State              : in out FBVBS.ABI.Manifest_Set_Record;
       Artifact_Object_Id : FBVBS.ABI.Handle;
       Manifest_Object_Id : FBVBS.ABI.Handle;
       Tail_Zero          : Boolean;
       Hash_Matches       : Boolean;
       Status             : out FBVBS.ABI.Status_Code)
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
              State.Approved_Artifact_Object_Id = Artifact_Object_Id
              and then State.Approved_Manifest_Object_Id = Manifest_Object_Id
           else
              State = State'Old);

    procedure Require_Artifact_Approval
      (State              : FBVBS.ABI.Manifest_Set_Record;
       Artifact_Object_Id : FBVBS.ABI.Handle;
       Manifest_Object_Id : FBVBS.ABI.Handle;
       Status             : out FBVBS.ABI.Status_Code)
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
              State.Approved_Artifact_Object_Id = Artifact_Object_Id
              and then State.Approved_Manifest_Object_Id = Manifest_Object_Id);

    procedure Check_Revocation
      (State        : in out FBVBS.ABI.Manifest_Set_Record;
       Object_Id    : FBVBS.ABI.Handle;
       Known_Object : Boolean;
       Revoked      : out Boolean;
       Status       : out FBVBS.ABI.Status_Code)
      with Post => (if Status /= FBVBS.ABI.OK then State = State'Old);
end FBVBS.UVS;
