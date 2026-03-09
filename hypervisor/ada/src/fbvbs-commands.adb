with FBVBS.ABI;

package body FBVBS.Commands
  with SPARK_Mode
is
   use type FBVBS.ABI.Partition_Kind;
   use type FBVBS.ABI.Host_Caller_Class;
   use type FBVBS.ABI.Trusted_Service_Kind;

   procedure Initialize (Tracker : out FBVBS.ABI.Command_Tracker_Record) is
   begin
      Tracker := (Sequence_Seen => False, Last_Sequence => 0, Last_Nonce => 0);
   end Initialize;

   procedure Begin_Dispatch
     (Tracker              : in out FBVBS.ABI.Command_Tracker_Record;
      State                : in out FBVBS.ABI.Command_State;
      Actual_Output_Length : FBVBS.ABI.U32;
      Caller_Sequence      : FBVBS.ABI.U64;
      Caller_Nonce         : FBVBS.ABI.U64;
      Status               : out FBVBS.ABI.Status_Code)
   is
   begin
      if State = FBVBS.ABI.Command_Executing then
         Status := FBVBS.ABI.Resource_Busy;
      elsif State /= FBVBS.ABI.Command_Ready
        and then State /= FBVBS.ABI.Command_Completed
        and then State /= FBVBS.ABI.Command_Failed
      then
          Status := FBVBS.ABI.Invalid_Parameter;
      elsif Actual_Output_Length /= 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Tracker.Sequence_Seen and then Caller_Sequence <= Tracker.Last_Sequence then
         Status := FBVBS.ABI.Replay_Detected;
      else
         Tracker.Sequence_Seen := True;
         Tracker.Last_Sequence := Caller_Sequence;
         Tracker.Last_Nonce := Caller_Nonce;
         State := FBVBS.ABI.Command_Executing;
         Status := FBVBS.ABI.OK;
      end if;
   end Begin_Dispatch;

   procedure Validate_Separate_Output
     (Owner                     : FBVBS.ABI.Partition_Descriptor;
      Output_Page_Aligned       : Boolean;
      Mapping_Writable          : Boolean;
      Reserved_Sharing_Writable : Boolean;
      Output_Length_Max         : FBVBS.ABI.U32;
      Required_Length           : FBVBS.ABI.U32;
      Status                    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Owner.In_Use then
         Status := FBVBS.ABI.Invalid_Caller;
      elsif not Output_Page_Aligned or else
        not Mapping_Writable or else
        not Reserved_Sharing_Writable
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Output_Length_Max < Required_Length then
         Status := FBVBS.ABI.Buffer_Too_Small;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Validate_Separate_Output;

   procedure Validate_Caller
     (Owner                 : in out FBVBS.ABI.Partition_Descriptor;
      Require_Host          : Boolean;
      Required_Service_Kind : FBVBS.ABI.Trusted_Service_Kind;
      Status                : out FBVBS.ABI.Status_Code)
   is
   begin
      if Required_Service_Kind /= FBVBS.ABI.Service_None then
         if not Owner.In_Use then
            Status := FBVBS.ABI.Invalid_Caller;
         elsif Owner.Kind = FBVBS.ABI.Partition_FreeBSD_Host then
            Status := FBVBS.ABI.OK;
         elsif Owner.Kind /= FBVBS.ABI.Partition_Trusted_Service then
            Status := FBVBS.ABI.Invalid_Caller;
         elsif Owner.Service_Kind /= Required_Service_Kind then
            Status := FBVBS.ABI.Invalid_Caller;
         else
            Status := FBVBS.ABI.OK;
         end if;
      elsif Require_Host then
         if not Owner.In_Use or else Owner.Kind /= FBVBS.ABI.Partition_FreeBSD_Host then
            Status := FBVBS.ABI.Invalid_Caller;
         else
            Status := FBVBS.ABI.OK;
         end if;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Validate_Caller;

    procedure Validate_Host_Callsite
      (Observed_RIP   : FBVBS.ABI.U64;
       Primary_Callsite : FBVBS.ABI.U64;
       Secondary_Callsite : FBVBS.ABI.U64;
       Required_Class : FBVBS.ABI.Host_Caller_Class;
       Status         : out FBVBS.ABI.Status_Code)
    is
    begin
       case Required_Class is
          when FBVBS.ABI.Host_Caller_FBVBS =>
             if Observed_RIP = Primary_Callsite or else
               Observed_RIP = Secondary_Callsite
             then
                Status := FBVBS.ABI.OK;
             else
                Status := FBVBS.ABI.Callsite_Rejected;
             end if;
          when FBVBS.ABI.Host_Caller_VMM =>
             if Observed_RIP = Primary_Callsite or else
               Observed_RIP = Secondary_Callsite
             then
                Status := FBVBS.ABI.OK;
             else
               Status := FBVBS.ABI.Callsite_Rejected;
            end if;
         when FBVBS.ABI.Host_Caller_None =>
            Status := FBVBS.ABI.Invalid_Parameter;
      end case;
   end Validate_Host_Callsite;

   procedure Finish_Dispatch
     (State                : in out FBVBS.ABI.Command_State;
      Hypercall_Status     : FBVBS.ABI.Status_Code;
      Actual_Output_Length : FBVBS.ABI.U32)
   is
      pragma Unreferenced (Actual_Output_Length);
   begin
      if Hypercall_Status = FBVBS.ABI.OK then
         State := FBVBS.ABI.Command_Completed;
      else
         State := FBVBS.ABI.Command_Failed;
      end if;
   end Finish_Dispatch;
end FBVBS.Commands;
