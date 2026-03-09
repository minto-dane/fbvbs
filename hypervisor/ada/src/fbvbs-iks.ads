with FBVBS.ABI;

package FBVBS.IKS
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Key_Type;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.Key_Record;

   procedure Initialize (State : out FBVBS.ABI.Key_Record)
     with Post => not State.In_Use;

   procedure Import_Key
     (State       : in out FBVBS.ABI.Key_Record;
      Key_Handle  : FBVBS.ABI.Handle;
      Key_Kind    : FBVBS.ABI.Key_Type;
      Allowed_Ops : FBVBS.ABI.U32;
      Key_Length  : FBVBS.ABI.U32;
      Status      : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.In_Use
             and then State.Key_Handle = Key_Handle
             and then State.Key_Kind = Key_Kind
             and then State.Allowed_Ops = Allowed_Ops
             and then State.Key_Length = Key_Length
          else
             State = State'Old);

   procedure Sign
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
     with Post => (if Status /= FBVBS.ABI.OK then State = State'Old);

   procedure Key_Exchange
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
     with Post => (if Status /= FBVBS.ABI.OK then State = State'Old);

   procedure Derive
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
     with Post => (if Status /= FBVBS.ABI.OK then State = State'Old);

   procedure Destroy_Key
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
     with Post => (if Status = FBVBS.ABI.OK then not State.In_Use);
end FBVBS.IKS;
