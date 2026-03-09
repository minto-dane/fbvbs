with FBVBS.ABI;

package body FBVBS.KSI_Shadow
  with SPARK_Mode
is
   procedure Initialize (State : out FBVBS.ABI.KSI_Shadow_State_Record) is
   begin
      State :=
        (Update_In_Progress => False,
         Shadow_Object_Id   => 0,
         Candidate_Object_Id => 0,
         Observed_RIP       => 0,
         Writers_Paused     => False,
         Write_Window_Open  => False);
   end Initialize;

   procedure Prepare_Update
     (Targets            : FBVBS.ABI.Target_Set_Record;
      State              : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Shadow_Object_Id   : FBVBS.ABI.Handle;
      Candidate_Object_Id : FBVBS.ABI.Handle;
      Observed_RIP       : FBVBS.ABI.U64;
      Allowed_Primary    : FBVBS.ABI.U64;
      Allowed_Secondary  : FBVBS.ABI.U64;
      Status             : out FBVBS.ABI.Status_Code)
   is
      Candidate_Allowed : constant Boolean :=
        (Candidate_Object_Id = Targets.First_Target_Object_Id and then Targets.First_Target_Registered)
        or else
        (Candidate_Object_Id = Targets.Second_Target_Object_Id and then Targets.Second_Target_Registered);
   begin
      if State.Update_In_Progress then
         Status := FBVBS.ABI.Resource_Busy;
      elsif not Targets.In_Use or else Targets.Pointer_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_State;
      elsif Shadow_Object_Id = 0 or else Candidate_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Observed_RIP /= Allowed_Primary and then Observed_RIP /= Allowed_Secondary then
         Status := FBVBS.ABI.Callsite_Rejected;
      elsif not Candidate_Allowed then
         Status := FBVBS.ABI.Policy_Denied;
      else
         State.Update_In_Progress := True;
         State.Shadow_Object_Id := Shadow_Object_Id;
         State.Candidate_Object_Id := Candidate_Object_Id;
         State.Observed_RIP := Observed_RIP;
         State.Writers_Paused := False;
         State.Write_Window_Open := False;
         Status := FBVBS.ABI.OK;
      end if;
   end Prepare_Update;

   procedure Pause_Writers
     (State  : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.Update_In_Progress or else State.Writers_Paused then
         Status := FBVBS.ABI.Invalid_State;
      else
         State.Writers_Paused := True;
         Status := FBVBS.ABI.OK;
      end if;
   end Pause_Writers;

   procedure Open_Write_Window
     (State  : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.Update_In_Progress or else not State.Writers_Paused or else State.Write_Window_Open then
         Status := FBVBS.ABI.Invalid_State;
      else
         State.Write_Window_Open := True;
         Status := FBVBS.ABI.OK;
      end if;
   end Open_Write_Window;

   procedure Commit_Update
     (Targets : in out FBVBS.ABI.Target_Set_Record;
      State   : in out FBVBS.ABI.KSI_Shadow_State_Record;
      Status  : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.Update_In_Progress or else not State.Writers_Paused or else not State.Write_Window_Open then
         Status := FBVBS.ABI.Invalid_State;
      elsif State.Candidate_Object_Id /= Targets.First_Target_Object_Id
        and then State.Candidate_Object_Id /= Targets.Second_Target_Object_Id
      then
         Status := FBVBS.ABI.Policy_Denied;
      else
         Targets.Replacement_Object_Id := State.Candidate_Object_Id;
         Targets.Active_Target_Object_Id := State.Candidate_Object_Id;
         Initialize (State);
         Status := FBVBS.ABI.OK;
      end if;
   end Commit_Update;

   procedure Abort_Update
     (State : in out FBVBS.ABI.KSI_Shadow_State_Record)
   is
   begin
      Initialize (State);
   end Abort_Update;
end FBVBS.KSI_Shadow;
