with FBVBS.ABI;

package body FBVBS.KSI
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U8;

   function Valid_Object_Reference
     (Object_Id, Guest_Physical_Address, Size : FBVBS.ABI.U64) return Boolean is
      (Object_Id /= 0
       and then Object_Id = Guest_Physical_Address
       and then Size /= 0
       and then (Guest_Physical_Address mod FBVBS.ABI.Page_Size) = 0
       and then (Size mod FBVBS.ABI.Page_Size) = 0);

   function Valid_Protection_Class (Protection_Class : FBVBS.ABI.U32) return Boolean is
      (Protection_Class = FBVBS.ABI.KSI_Class_UCRED
       or else Protection_Class = FBVBS.ABI.KSI_Class_Prison
       or else Protection_Class = FBVBS.ABI.KSI_Class_Securelevel
       or else Protection_Class = FBVBS.ABI.KSI_Class_MAC
       or else Protection_Class = FBVBS.ABI.KSI_Class_Capsicum
       or else Protection_Class = FBVBS.ABI.KSI_Class_Firewall
       or else Protection_Class = FBVBS.ABI.KSI_Class_P_TextVP);

   function Find_Object_Slot
     (State : FBVBS.ABI.Target_Set_Record;
      Object_Id : FBVBS.ABI.Handle) return Integer
   is
   begin
      for Index in State.Objects'Range loop
         if State.Objects (Index).Active
           and then State.Objects (Index).Object_Id = Object_Id
         then
            return Integer (Index);
         end if;
      end loop;

      return -1;
   end Find_Object_Slot;

   function Find_Free_Object_Slot
     (State : FBVBS.ABI.Target_Set_Record) return Integer
   is
   begin
      for Index in State.Objects'Range loop
         if not State.Objects (Index).Active then
            return Integer (Index);
         end if;
      end loop;

      return -1;
   end Find_Free_Object_Slot;

   function Protection_Class_For
     (State : FBVBS.ABI.Target_Set_Record;
      Object_Id : FBVBS.ABI.Handle) return FBVBS.ABI.U32
   is
      Slot : constant Integer := Find_Object_Slot (State, Object_Id);
   begin
      if Slot < 0 then
         return 0;
      else
         return State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Protection_Class;
      end if;
   end Protection_Class_For;

   function Object_Is_Registered
     (State : FBVBS.ABI.Target_Set_Record;
      Object_Id : FBVBS.ABI.Handle) return Boolean is
      (Find_Object_Slot (State, Object_Id) >= 0);

   function Compatible_Protection_Classes
     (Active_Protection_Class, Candidate_Protection_Class : FBVBS.ABI.U32) return Boolean is
      ((Active_Protection_Class = 0 and then Candidate_Protection_Class = 0)
       or else
       (Active_Protection_Class /= 0
        and then Candidate_Protection_Class /= 0
        and then Active_Protection_Class = Candidate_Protection_Class));

   function Hash_Tail_Zero (Measured_Hash : FBVBS.ABI.Hash_Buffer) return Boolean is
   begin
      for Index in 48 .. 63 loop
         if Measured_Hash (Index) /= 0 then
            return False;
         end if;
      end loop;

      return True;
   end Hash_Tail_Zero;

   function Hash_Has_Payload (Measured_Hash : FBVBS.ABI.Hash_Buffer) return Boolean is
   begin
      for Index in 0 .. 47 loop
         if Measured_Hash (Index) /= 0 then
            return True;
         end if;
      end loop;

      return False;
   end Hash_Has_Payload;

   procedure Register_Object
     (State                  : in out FBVBS.ABI.Target_Set_Record;
      Object_Id              : FBVBS.ABI.Handle;
      Guest_Physical_Address : FBVBS.ABI.U64;
      Size                   : FBVBS.ABI.U64;
      Tier_B                 : Boolean;
      Protection_Class       : FBVBS.ABI.U32;
      Status                 : out FBVBS.ABI.Status_Code)
   is
      Slot : constant Integer := Find_Free_Object_Slot (State);
   begin
      if Find_Object_Slot (State, Object_Id) >= 0 then
         Status := FBVBS.ABI.Already_Exists;
      elsif Slot < 0 then
         Status := FBVBS.ABI.Resource_Exhausted;
      else
         State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)) :=
           (Active                 => True,
            Tier_B                 => Tier_B,
            Pointer_Registered     => False,
            Retired                => False,
            Protection_Class       => Protection_Class,
            Object_Id              => Object_Id,
            Guest_Physical_Address => Guest_Physical_Address,
            Size                   => Size,
            Target_Set_Id          => State.Target_Set_Id);
         Status := FBVBS.ABI.OK;
      end if;
   end Register_Object;

   procedure Initialize (State : out FBVBS.ABI.Target_Set_Record) is
   begin
      State :=
        (In_Use                  => False,
         Target_Set_Id           => 0,
         Target_Count            => 0,
         First_Target_Object_Id  => 0,
         Second_Target_Object_Id => 0,
         First_Target_Registered => False,
         Second_Target_Registered => False,
         First_Target_Protection_Class => 0,
         Second_Target_Protection_Class => 0,
         Pointer_Object_Id       => 0,
         Active_Target_Object_Id => 0,
         Replacement_Object_Id   => 0,
         Objects                 => (others => (others => <>)),
         Next_KSI_Object_Id      => 16#20000#);
   end Initialize;

   procedure Create_Target_Set
     (State                   : in out FBVBS.ABI.Target_Set_Record;
      Target_Set_Id           : FBVBS.ABI.Handle;
      First_Target_Object_Id  : FBVBS.ABI.Handle;
      Second_Target_Object_Id : FBVBS.ABI.Handle;
      Target_Count            : FBVBS.ABI.Target_Count_Type;
      Status                  : out FBVBS.ABI.Status_Code)
   is
   begin
      if State.In_Use then
         Status := FBVBS.ABI.Invalid_State;
         return;
      end if;

      if Target_Set_Id = 0 or else Target_Count = 0 or else First_Target_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      if Target_Count = 2 then
         if Second_Target_Object_Id = 0 or else Second_Target_Object_Id = First_Target_Object_Id then
            Status := FBVBS.ABI.Already_Exists;
            return;
         end if;
      elsif Second_Target_Object_Id /= 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
         return;
      end if;

      State.In_Use := True;
      State.Target_Set_Id := Target_Set_Id;
      State.Target_Count := Target_Count;
      State.First_Target_Object_Id := First_Target_Object_Id;
      State.Second_Target_Object_Id := Second_Target_Object_Id;
      State.Active_Target_Object_Id := First_Target_Object_Id;
      Status := FBVBS.ABI.OK;
   end Create_Target_Set;

   procedure Register_Target_Object
     (State                  : in out FBVBS.ABI.Target_Set_Record;
      Object_Id              : FBVBS.ABI.Handle;
      Guest_Physical_Address : FBVBS.ABI.U64;
      Size                   : FBVBS.ABI.U64;
      Status                 : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use or else State.Target_Set_Id = 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif not Valid_Object_Reference (Object_Id, Guest_Physical_Address, Size) then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Register_Object
           (State                  => State,
            Object_Id              => Object_Id,
            Guest_Physical_Address => Guest_Physical_Address,
            Size                   => Size,
            Tier_B                 => False,
            Protection_Class       => 0,
            Status                 => Status);
         if Status = FBVBS.ABI.OK then
            if Object_Id = State.First_Target_Object_Id then
               State.First_Target_Registered := True;
               State.First_Target_Protection_Class := 0;
            elsif Object_Id = State.Second_Target_Object_Id and then State.Target_Count = 2 then
               State.Second_Target_Registered := True;
               State.Second_Target_Protection_Class := 0;
            end if;
         end if;
      end if;
   end Register_Target_Object;

   procedure Register_Tier_B_Object
     (State                  : in out FBVBS.ABI.Target_Set_Record;
      Object_Id              : FBVBS.ABI.Handle;
      Guest_Physical_Address : FBVBS.ABI.U64;
      Size                   : FBVBS.ABI.U64;
      Protection_Class       : FBVBS.ABI.U32;
      Status                 : out FBVBS.ABI.Status_Code)
   is
   begin
      if not State.In_Use or else State.Target_Set_Id = 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif not Valid_Object_Reference (Object_Id, Guest_Physical_Address, Size)
        or else not Valid_Protection_Class (Protection_Class)
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Register_Object
           (State                  => State,
            Object_Id              => Object_Id,
            Guest_Physical_Address => Guest_Physical_Address,
            Size                   => Size,
            Tier_B                 => True,
            Protection_Class       => Protection_Class,
            Status                 => Status);
         if Status = FBVBS.ABI.OK then
            if Object_Id = State.First_Target_Object_Id then
               State.First_Target_Registered := True;
               State.First_Target_Protection_Class := Protection_Class;
            elsif Object_Id = State.Second_Target_Object_Id and then State.Target_Count = 2 then
               State.Second_Target_Registered := True;
               State.Second_Target_Protection_Class := Protection_Class;
            end if;
         end if;
      end if;
   end Register_Tier_B_Object;

   procedure Modify_Tier_B_Object
     (State        : FBVBS.ABI.Target_Set_Record;
      Object_Id    : FBVBS.ABI.Handle;
      Patch_Length : FBVBS.ABI.U32;
      Status       : out FBVBS.ABI.Status_Code)
   is
      Slot : constant Integer := Find_Object_Slot (State, Object_Id);
   begin
      if Object_Id = 0 or else Patch_Length = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Slot < 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif not State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Tier_B
        or else State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Retired
      then
         Status := FBVBS.ABI.Invalid_State;
      elsif FBVBS.ABI.U64 (Patch_Length) > State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Size then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Modify_Tier_B_Object;

   procedure Register_Pointer
     (State             : in out FBVBS.ABI.Target_Set_Record;
      Pointer_Object_Id : FBVBS.ABI.Handle;
      Status            : out FBVBS.ABI.Status_Code)
   is
      Slot : constant Integer := Find_Object_Slot (State, Pointer_Object_Id);
   begin
      if not State.In_Use or else Pointer_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Slot < 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Pointer_Registered then
         Status := FBVBS.ABI.Already_Exists;
      elsif not State.First_Target_Registered and then not State.Second_Target_Registered then
         Status := FBVBS.ABI.Not_Found;
      else
         State.Pointer_Object_Id := Pointer_Object_Id;
         State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Pointer_Registered := True;
         State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Target_Set_Id := State.Target_Set_Id;
         Status := FBVBS.ABI.OK;
      end if;
   end Register_Pointer;

   procedure Allocate_Ucred
     (State                    : in out FBVBS.ABI.Target_Set_Record;
      Requested_UID            : FBVBS.ABI.U32;
      Requested_GID            : FBVBS.ABI.U32;
      Prison_Object_Id         : FBVBS.ABI.Handle;
      Template_Ucred_Object_Id : FBVBS.ABI.Handle;
      Ucred_Object_Id          : out FBVBS.ABI.Handle;
      Status                   : out FBVBS.ABI.Status_Code)
   is
      Free_Slot      : constant Integer := Find_Free_Object_Slot (State);
      Prison_Slot    : constant Integer := Find_Object_Slot (State, Prison_Object_Id);
      Template_Slot  : constant Integer := Find_Object_Slot (State, Template_Ucred_Object_Id);
   begin
      pragma Unreferenced (Requested_UID, Requested_GID);
      Ucred_Object_Id := 0;

      if not State.In_Use or else State.Target_Set_Id = 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif Prison_Object_Id = 0 or else Prison_Slot < 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif Template_Ucred_Object_Id /= 0 and then Template_Slot < 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif Template_Ucred_Object_Id /= 0
        and then
          (not State.Objects (FBVBS.ABI.KSI_Object_Slot (Template_Slot)).Tier_B
           or else State.Objects (FBVBS.ABI.KSI_Object_Slot (Template_Slot)).Protection_Class /= FBVBS.ABI.KSI_Class_UCRED)
      then
         Status := FBVBS.ABI.Policy_Denied;
      elsif Free_Slot < 0 or else State.Next_KSI_Object_Id = 0 then
         Status := FBVBS.ABI.Resource_Exhausted;
      else
         Ucred_Object_Id := State.Next_KSI_Object_Id;
         State.Objects (FBVBS.ABI.KSI_Object_Slot (Free_Slot)) :=
           (Active                 => True,
            Tier_B                 => True,
            Pointer_Registered     => False,
            Retired                => False,
            Protection_Class       => FBVBS.ABI.KSI_Class_UCRED,
            Object_Id              => Ucred_Object_Id,
            Guest_Physical_Address => Ucred_Object_Id,
            Size                   => FBVBS.ABI.Page_Size,
            Target_Set_Id          => State.Target_Set_Id);
         State.Next_KSI_Object_Id := State.Next_KSI_Object_Id + FBVBS.ABI.Page_Size;
         Status := FBVBS.ABI.OK;
      end if;
   end Allocate_Ucred;

   procedure Replace_Tier_B_Object
     (State         : in out FBVBS.ABI.Target_Set_Record;
      New_Object_Id : FBVBS.ABI.Handle;
      Status        : out FBVBS.ABI.Status_Code)
   is
      Active_Protection_Class : constant FBVBS.ABI.U32 :=
        Protection_Class_For (State, State.Active_Target_Object_Id);
      Candidate_Protection_Class : constant FBVBS.ABI.U32 :=
        Protection_Class_For (State, New_Object_Id);
      Pointer_Slot : constant Integer := Find_Object_Slot (State, State.Pointer_Object_Id);
      Candidate_Slot : constant Integer := Find_Object_Slot (State, New_Object_Id);
   begin
      if not State.In_Use or else New_Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif State.Pointer_Object_Id = 0
        or else Pointer_Slot < 0
        or else not State.Objects (FBVBS.ABI.KSI_Object_Slot (Pointer_Slot)).Pointer_Registered
      then
         Status := FBVBS.ABI.Invalid_State;
      elsif Candidate_Slot < 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif not State.Objects (FBVBS.ABI.KSI_Object_Slot (Candidate_Slot)).Tier_B then
         Status := FBVBS.ABI.Invalid_State;
      elsif not Compatible_Protection_Classes
        (Active_Protection_Class, Candidate_Protection_Class)
      then
         Status := FBVBS.ABI.Policy_Denied;
      elsif New_Object_Id = State.First_Target_Object_Id and then State.First_Target_Registered then
         State.Replacement_Object_Id := New_Object_Id;
         State.Active_Target_Object_Id := New_Object_Id;
         Status := FBVBS.ABI.OK;
      elsif New_Object_Id = State.Second_Target_Object_Id
        and then State.Target_Count = 2
        and then State.Second_Target_Registered
      then
         State.Replacement_Object_Id := New_Object_Id;
         State.Active_Target_Object_Id := New_Object_Id;
         Status := FBVBS.ABI.OK;
      else
         Status := FBVBS.ABI.Policy_Denied;
      end if;
   end Replace_Tier_B_Object;

   procedure Validate_Setuid
     (State                  : FBVBS.ABI.Target_Set_Record;
      Operation_Class        : FBVBS.ABI.U32;
      Valid_Mask             : FBVBS.ABI.U32;
      FSID                   : FBVBS.ABI.U64;
      File_Id                : FBVBS.ABI.U64;
      Measured_Hash          : FBVBS.ABI.Hash_Buffer;
      Requested_RUID         : FBVBS.ABI.U32;
      Requested_EUID         : FBVBS.ABI.U32;
      Requested_SUID         : FBVBS.ABI.U32;
      Requested_RGID         : FBVBS.ABI.U32;
      Requested_EGID         : FBVBS.ABI.U32;
      Requested_SGID         : FBVBS.ABI.U32;
      Caller_Ucred_Object_Id : FBVBS.ABI.Handle;
      Jail_Context_Id        : FBVBS.ABI.Handle;
      MAC_Context_Id         : FBVBS.ABI.Handle;
      Status                 : out FBVBS.ABI.Status_Code)
   is
      UID_Mask : constant FBVBS.ABI.U32 :=
        FBVBS.ABI.KSI_Valid_RUID or FBVBS.ABI.KSI_Valid_EUID or FBVBS.ABI.KSI_Valid_SUID;
      GID_Mask : constant FBVBS.ABI.U32 :=
        FBVBS.ABI.KSI_Valid_RGID or FBVBS.ABI.KSI_Valid_EGID or FBVBS.ABI.KSI_Valid_SGID;
      Invalid_Mask : constant FBVBS.ABI.U32 := 16#FFFF_FFC0#;
      Caller_Class : constant FBVBS.ABI.U32 :=
        Protection_Class_For (State, Caller_Ucred_Object_Id);
      Jail_Class : constant FBVBS.ABI.U32 := Protection_Class_For (State, Jail_Context_Id);
      MAC_Class : constant FBVBS.ABI.U32 := Protection_Class_For (State, MAC_Context_Id);
      Hash_Present : constant Boolean := Hash_Has_Payload (Measured_Hash);
      Has_File : constant Boolean := File_Id /= 0;
   begin
      pragma Unreferenced
        (Requested_RUID,
         Requested_EUID,
         Requested_SUID,
         Requested_RGID,
         Requested_EGID,
         Requested_SGID);

      if Valid_Mask = 0 or else (Valid_Mask and Invalid_Mask) /= 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Hash_Tail_Zero (Measured_Hash) then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif (FSID = 0 and then File_Id /= 0) or else (FSID /= 0 and then File_Id = 0) then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Object_Is_Registered (State, Caller_Ucred_Object_Id) then
         Status := FBVBS.ABI.Not_Found;
      elsif Caller_Class /= FBVBS.ABI.KSI_Class_UCRED then
         Status := FBVBS.ABI.Policy_Denied;
      elsif Jail_Context_Id /= 0 and then not Object_Is_Registered (State, Jail_Context_Id) then
         Status := FBVBS.ABI.Not_Found;
      elsif Jail_Context_Id /= 0 and then Jail_Class /= FBVBS.ABI.KSI_Class_Prison then
         Status := FBVBS.ABI.Policy_Denied;
      elsif MAC_Context_Id /= 0 and then not Object_Is_Registered (State, MAC_Context_Id) then
         Status := FBVBS.ABI.Not_Found;
      elsif MAC_Context_Id /= 0 and then MAC_Class /= FBVBS.ABI.KSI_Class_MAC then
         Status := FBVBS.ABI.Policy_Denied;
      elsif Operation_Class = FBVBS.ABI.KSI_Operation_Exec_Elevation then
         if not Has_File or else not Hash_Present then
            Status := FBVBS.ABI.Invalid_Parameter;
         elsif (Valid_Mask and (UID_Mask or GID_Mask)) = 0 then
            Status := FBVBS.ABI.Invalid_Parameter;
         else
            Status := FBVBS.ABI.OK;
         end if;
      elsif Operation_Class = FBVBS.ABI.KSI_Operation_Setuid_Family then
         if Has_File or else Hash_Present then
            Status := FBVBS.ABI.Invalid_Parameter;
         elsif (Valid_Mask and GID_Mask) /= 0 then
            Status := FBVBS.ABI.Policy_Denied;
         elsif (Valid_Mask and UID_Mask) = 0 then
            Status := FBVBS.ABI.Invalid_Parameter;
         else
            Status := FBVBS.ABI.OK;
         end if;
      elsif Operation_Class = FBVBS.ABI.KSI_Operation_Setgid_Family then
         if Has_File or else Hash_Present then
            Status := FBVBS.ABI.Invalid_Parameter;
         elsif (Valid_Mask and UID_Mask) /= 0 then
            Status := FBVBS.ABI.Policy_Denied;
         elsif (Valid_Mask and GID_Mask) = 0 then
            Status := FBVBS.ABI.Invalid_Parameter;
         else
            Status := FBVBS.ABI.OK;
         end if;
      else
         Status := FBVBS.ABI.Invalid_Parameter;
      end if;
   end Validate_Setuid;

   procedure Unregister_Object
     (State     : in out FBVBS.ABI.Target_Set_Record;
      Object_Id : FBVBS.ABI.Handle;
      Status    : out FBVBS.ABI.Status_Code)
   is
      Slot : constant Integer := Find_Object_Slot (State, Object_Id);
   begin
      if Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Slot < 0 then
         Status := FBVBS.ABI.Not_Found;
      elsif State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)).Pointer_Registered then
         Status := FBVBS.ABI.Resource_Busy;
      elsif Object_Id = State.Active_Target_Object_Id
        or else Object_Id = State.Replacement_Object_Id
        or else Object_Id = State.Pointer_Object_Id
        or else (Object_Id = State.First_Target_Object_Id and then State.First_Target_Registered)
        or else (Object_Id = State.Second_Target_Object_Id and then State.Second_Target_Registered)
      then
         Status := FBVBS.ABI.Resource_Busy;
      else
         State.Objects (FBVBS.ABI.KSI_Object_Slot (Slot)) := (others => <>);
         Status := FBVBS.ABI.OK;
      end if;
   end Unregister_Object;
end FBVBS.KSI;
