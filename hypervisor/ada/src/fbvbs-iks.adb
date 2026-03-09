with FBVBS.ABI;

package body FBVBS.IKS
  with SPARK_Mode
is
   procedure Initialize (State : out FBVBS.ABI.Key_Record) is
   begin
      State :=
        (In_Use      => False,
         Key_Handle  => 0,
         Key_Kind    => FBVBS.ABI.No_Key,
         Allowed_Ops => 0,
         Key_Length  => 0);
   end Initialize;

   procedure Import_Key
     (State       : in out FBVBS.ABI.Key_Record;
      Key_Handle  : FBVBS.ABI.Handle;
      Key_Kind    : FBVBS.ABI.Key_Type;
      Allowed_Ops : FBVBS.ABI.U32;
      Key_Length  : FBVBS.ABI.U32;
      Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      if State.In_Use then
         Status := FBVBS.ABI.Already_Exists;
         return;
      end if;

      if Key_Handle = 0
        or else Key_Kind = FBVBS.ABI.No_Key
        or else Allowed_Ops = 0
        or else not FBVBS.ABI.Valid_Key_Length (Key_Kind, Key_Length)
      then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      if (FBVBS.ABI.Has_Op (Allowed_Ops, FBVBS.ABI.IKS_Op_Sign)
          and then not FBVBS.ABI.Supports_Sign (Key_Kind))
        or else
         (FBVBS.ABI.Has_Op (Allowed_Ops, FBVBS.ABI.IKS_Op_Key_Exchange)
          and then not FBVBS.ABI.Supports_Key_Exchange (Key_Kind))
      then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      State.In_Use := True;
      State.Key_Handle := Key_Handle;
      State.Key_Kind := Key_Kind;
      State.Allowed_Ops := Allowed_Ops;
      State.Key_Length := Key_Length;
      Status := FBVBS.ABI.OK;
   end Import_Key;

   procedure Sign
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif not FBVBS.ABI.Has_Op (State.Allowed_Ops, FBVBS.ABI.IKS_Op_Sign) then
         Status := FBVBS.ABI.Permission_Denied;
      elsif not FBVBS.ABI.Supports_Sign (State.Key_Kind) then
         Status := FBVBS.ABI.Policy_Denied;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Sign;

   procedure Key_Exchange
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif not FBVBS.ABI.Has_Op (State.Allowed_Ops, FBVBS.ABI.IKS_Op_Key_Exchange) then
         Status := FBVBS.ABI.Permission_Denied;
      elsif not FBVBS.ABI.Supports_Key_Exchange (State.Key_Kind) then
         Status := FBVBS.ABI.Policy_Denied;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Key_Exchange;

   procedure Derive
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif not FBVBS.ABI.Has_Op (State.Allowed_Ops, FBVBS.ABI.IKS_Op_Derive) then
         Status := FBVBS.ABI.Permission_Denied;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Derive;

   procedure Destroy_Key
     (State  : in out FBVBS.ABI.Key_Record;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use then
         Status := FBVBS.ABI.Not_Found;
         return;
      end if;

      State.In_Use := False;
      State.Key_Handle := 0;
      State.Key_Kind := FBVBS.ABI.No_Key;
      State.Allowed_Ops := 0;
      State.Key_Length := 0;
      Status := FBVBS.ABI.OK;
   end Destroy_Key;
end FBVBS.IKS;
