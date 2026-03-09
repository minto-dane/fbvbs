with FBVBS.ABI;

package FBVBS.Commands
  with SPARK_Mode
is
   use type FBVBS.ABI.Command_State;
   use type FBVBS.ABI.Command_Tracker_Record;
   use type FBVBS.ABI.Host_Caller_Class;
   use type FBVBS.ABI.Partition_Kind;
   use type FBVBS.ABI.Partition_Descriptor;
   use type FBVBS.ABI.Trusted_Service_Kind;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;

   procedure Initialize (Tracker : out FBVBS.ABI.Command_Tracker_Record)
     with
       Post => not Tracker.Sequence_Seen;

   procedure Begin_Dispatch
     (Tracker              : in out FBVBS.ABI.Command_Tracker_Record;
      State                : in out FBVBS.ABI.Command_State;
      Actual_Output_Length : FBVBS.ABI.U32;
      Caller_Sequence      : FBVBS.ABI.U64;
      Caller_Nonce         : FBVBS.ABI.U64;
      Status               : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State = FBVBS.ABI.Command_Executing and then
             Tracker.Sequence_Seen and then
             Tracker.Last_Sequence = Caller_Sequence and then
             Tracker.Last_Nonce = Caller_Nonce
          else
             State = State'Old and then
             Tracker = Tracker'Old);

   procedure Validate_Separate_Output
     (Owner                     : FBVBS.ABI.Partition_Descriptor;
      Output_Page_Aligned       : Boolean;
      Mapping_Writable          : Boolean;
      Reserved_Sharing_Writable : Boolean;
      Output_Length_Max         : FBVBS.ABI.U32;
      Required_Length           : FBVBS.ABI.U32;
      Status                    : out FBVBS.ABI.Status_Code)
     with
       Post =>
          (if Status = FBVBS.ABI.OK then
              Owner.In_Use
              and then Output_Page_Aligned
              and then Mapping_Writable
              and then Reserved_Sharing_Writable
              and then Output_Length_Max >= Required_Length);

   procedure Validate_Caller
     (Owner                 : in out FBVBS.ABI.Partition_Descriptor;
      Require_Host          : Boolean;
      Required_Service_Kind : FBVBS.ABI.Trusted_Service_Kind;
      Status                : out FBVBS.ABI.Status_Code)
     with
       Pre =>
         not (Require_Host and then Required_Service_Kind /= FBVBS.ABI.Service_None),
       Post =>
          (if Status = FBVBS.ABI.OK and then
              Required_Service_Kind /= FBVBS.ABI.Service_None
           then
              Owner.In_Use and then
              (Owner.Kind = FBVBS.ABI.Partition_FreeBSD_Host or else
               Owner.Service_Kind = Required_Service_Kind)
           elsif Status = FBVBS.ABI.OK and then Require_Host
           then
              Owner.In_Use
          else
             True);

   procedure Validate_Host_Callsite
      (Observed_RIP   : FBVBS.ABI.U64;
       Primary_Callsite : FBVBS.ABI.U64;
       Secondary_Callsite : FBVBS.ABI.U64;
       Required_Class : FBVBS.ABI.Host_Caller_Class;
       Status         : out FBVBS.ABI.Status_Code)
      with
        Post =>
         (if Status = FBVBS.ABI.OK then
             Required_Class /= FBVBS.ABI.Host_Caller_None);

   procedure Finish_Dispatch
     (State                : in out FBVBS.ABI.Command_State;
      Hypercall_Status     : FBVBS.ABI.Status_Code;
      Actual_Output_Length : FBVBS.ABI.U32)
     with
       Post =>
         (if Hypercall_Status = FBVBS.ABI.OK then
             State = FBVBS.ABI.Command_Completed
          else
             State = FBVBS.ABI.Command_Failed);
end FBVBS.Commands;
