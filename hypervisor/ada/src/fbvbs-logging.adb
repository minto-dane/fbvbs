with FBVBS.ABI;

package body FBVBS.Logging
  with SPARK_Mode
is
   procedure Initialize
     (State      : in out FBVBS.ABI.Log_State_Record;
      Boot_Id_Hi : FBVBS.ABI.U64;
      Boot_Id_Lo : FBVBS.ABI.U64;
      Status     : out FBVBS.ABI.Status_Code)
   is
   begin
      State.Initialized := True;
      State.Write_Offset := 0;
      State.Max_Readable_Sequence := 0;
      State.Boot_Id_Hi := Boot_Id_Hi;
      State.Boot_Id_Lo := Boot_Id_Lo;
      Status := FBVBS.ABI.OK;
   end Initialize;

    procedure Append_Record
      (State          : in out FBVBS.ABI.Log_State_Record;
       Payload_Length : FBVBS.ABI.U32;
       Status         : out FBVBS.ABI.Status_Code)
   is
      Next_Sequence : FBVBS.ABI.U64;
      Slot_Index    : FBVBS.ABI.U32;
   begin
      if not State.Initialized then
         Status := FBVBS.ABI.Invalid_State;
      elsif Payload_Length > FBVBS.ABI.Log_Payload_Max then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Next_Sequence := State.Max_Readable_Sequence + 1;
         Slot_Index :=
           FBVBS.ABI.U32 ((Next_Sequence - 1) mod FBVBS.ABI.U64 (FBVBS.ABI.Log_Slot_Count));
         State.Max_Readable_Sequence := Next_Sequence;
          State.Write_Offset := Slot_Index * FBVBS.ABI.Log_Record_Size;
          Status := FBVBS.ABI.OK;
       end if;
    end Append_Record;

   procedure Get_Mirror_Info
     (State  : FBVBS.ABI.Log_State_Record;
      Result : out FBVBS.ABI.Audit_Mirror_Info_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      Result := (Ring_GPA => 0, Ring_Size => 0, Record_Size => 0);
      if not State.Initialized then
         Status := FBVBS.ABI.Invalid_State;
      else
         Result :=
           (Ring_GPA    => FBVBS.ABI.Mirror_Log_Ring_GPA,
            Ring_Size   => FBVBS.ABI.Log_Ring_Total_Size,
            Record_Size => FBVBS.ABI.Log_Record_Size);
         Status := FBVBS.ABI.OK;
      end if;
   end Get_Mirror_Info;
end FBVBS.Logging;
