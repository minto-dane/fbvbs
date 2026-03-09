with FBVBS.ABI;

package FBVBS.KSI_Shadow
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.KSI_Shadow_State_Record;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.Target_Set_Record;
   use type FBVBS.ABI.U64;

   procedure Initialize (State : out FBVBS.ABI.KSI_Shadow_State_Record)
     with Post => not State.Update_In_Progress;

   procedure Prepare_Update
     (Targets            : FBVBS.ABI.Target_Set_Record;
      State              : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Shadow_Object_Id   : FBVBS.ABI.Handle;
      Candidate_Object_Id : FBVBS.ABI.Handle;
      Observed_RIP       : FBVBS.ABI.U64;
      Allowed_Primary    : FBVBS.ABI.U64;
      Allowed_Secondary  : FBVBS.ABI.U64;
      Status             : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.Update_In_Progress
             and then State.Shadow_Object_Id = Shadow_Object_Id
             and then State.Candidate_Object_Id = Candidate_Object_Id
          else
             State = State'Old);

   procedure Pause_Writers
     (State  : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Status : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.Writers_Paused
          else
             State = State'Old);

   procedure Open_Write_Window
     (State  : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Status : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.Write_Window_Open
          else
             State = State'Old);

   procedure Commit_Update
     (Targets : in out FBVBS.ABI.Target_Set_Record;
      State   : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Status  : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             Targets.Active_Target_Object_Id = Targets.Replacement_Object_Id
             and then not State.Update_In_Progress
          else
             Targets = Targets'Old and then State = State'Old);

   procedure Abort_Update
     (State : in out FBVBS.ABI.KSI_Shadow_State_Record)
     with Post => not State.Update_In_Progress;
end FBVBS.KSI_Shadow;
