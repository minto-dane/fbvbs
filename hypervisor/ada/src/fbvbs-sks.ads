with FBVBS.ABI;

package FBVBS.SKS
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;
   use type FBVBS.ABI.Dek_Record;

   procedure Initialize (State : out FBVBS.ABI.Dek_Record)
     with Post => not State.In_Use;

   procedure Import_DEK
     (State      : in out FBVBS.ABI.Dek_Record;
      Dek_Handle : FBVBS.ABI.Handle;
      Volume_Id  : FBVBS.ABI.U64;
      Key_Length : FBVBS.ABI.U32;
      Status     : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.In_Use
             and then State.Dek_Handle = Dek_Handle
             and then State.Volume_Id = Volume_Id
             and then State.Key_Length = Key_Length
          else
             State = State'Old);

   procedure Process_Batch
     (State           : in out FBVBS.ABI.Dek_Record;
      Descriptor_Count : FBVBS.ABI.U32;
      Page_Aligned    : Boolean;
      Status          : out FBVBS.ABI.Status_Code)
     with Post => (if Status /= FBVBS.ABI.OK then State = State'Old);

   procedure Destroy_DEK
     (State  : in out FBVBS.ABI.Dek_Record;
      Status : out FBVBS.ABI.Status_Code)
     with Post => (if Status = FBVBS.ABI.OK then not State.In_Use);
end FBVBS.SKS;
