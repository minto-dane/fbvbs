with FBVBS.ABI;

package body FBVBS.SKS
  with SPARK_Mode
is
   procedure Initialize (State : out FBVBS.ABI.Dek_Record) is
   begin
      State := (In_Use => False, Dek_Handle => 0, Volume_Id => 0, Key_Length => 0);
   end Initialize;

   procedure Import_DEK
     (State      : in out FBVBS.ABI.Dek_Record;
      Dek_Handle : FBVBS.ABI.Handle;
      Volume_Id  : FBVBS.ABI.U64;
      Key_Length : FBVBS.ABI.U32;
      Status     : out FBVBS.ABI.Status_Code)
   is
   begin
      if State.In_Use then
         Status := FBVBS.ABI.Already_Exists;
         return;
      end if;

      if Dek_Handle = 0
        or else Volume_Id = 0
        or else (Key_Length /= 16 and then Key_Length /= 32)
      then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      State.In_Use := True;
      State.Dek_Handle := Dek_Handle;
      State.Volume_Id := Volume_Id;
      State.Key_Length := Key_Length;
      Status := FBVBS.ABI.OK;
   end Import_DEK;

   procedure Process_Batch
     (State           : in out FBVBS.ABI.Dek_Record;
      Descriptor_Count : FBVBS.ABI.U32;
      Page_Aligned    : Boolean;
      Status          : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif Descriptor_Count = 0 or else Descriptor_Count > 128 or else not Page_Aligned then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Process_Batch;

   procedure Destroy_DEK
     (State  : in out FBVBS.ABI.Dek_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use then
         Status := FBVBS.ABI.Not_Found;
         return;
      end if;

      State.In_Use := False;
      State.Dek_Handle := 0;
      State.Volume_Id := 0;
      State.Key_Length := 0;
      Status := FBVBS.ABI.OK;
   end Destroy_DEK;
end FBVBS.SKS;
