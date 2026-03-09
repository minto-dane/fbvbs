with FBVBS.ABI;

package FBVBS.Logging
  with SPARK_Mode
is
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;

   procedure Initialize
     (State      : in out FBVBS.ABI.Log_State_Record;
      Boot_Id_Hi : FBVBS.ABI.U64;
      Boot_Id_Lo : FBVBS.ABI.U64;
      Status     : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
              State.Initialized
              and then State.Write_Offset = 0
              and then State.Max_Readable_Sequence = 0
              and then State.Boot_Id_Hi = Boot_Id_Hi
              and then State.Boot_Id_Lo = Boot_Id_Lo);

    procedure Append_Record
      (State          : in out FBVBS.ABI.Log_State_Record;
       Payload_Length : FBVBS.ABI.U32;
       Status         : out FBVBS.ABI.Status_Code)
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
               State.Max_Readable_Sequence = State.Max_Readable_Sequence'Old + 1
               and then State.Write_Offset mod FBVBS.ABI.Log_Record_Size = 0);

   procedure Get_Mirror_Info
     (State  : FBVBS.ABI.Log_State_Record;
      Result : out FBVBS.ABI.Audit_Mirror_Info_Record;
      Status : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             Result.Ring_GPA = FBVBS.ABI.Mirror_Log_Ring_GPA
             and then Result.Ring_Size = FBVBS.ABI.Log_Ring_Total_Size
             and then Result.Record_Size = FBVBS.ABI.Log_Record_Size);
end FBVBS.Logging;
