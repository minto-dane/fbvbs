with FBVBS.ABI;

package body FBVBS.Memory
  with SPARK_Mode
is
   use type FBVBS.ABI.Partition_Kind;
   use type FBVBS.ABI.Partition_State;

   function Has_All_Bits (Value : FBVBS.ABI.U64; Mask : FBVBS.ABI.U64) return Boolean is
     ((Value and Mask) = Mask);

   function Valid_Permissions (Permissions : FBVBS.ABI.U32) return Boolean is
      Allowed : constant FBVBS.ABI.U32 :=
        FBVBS.ABI.Memory_Permission_Read
        or FBVBS.ABI.Memory_Permission_Write
        or FBVBS.ABI.Memory_Permission_Execute;
   begin
      return Permissions /= 0
        and then (Permissions and not Allowed) = 0
        and then
          ((Permissions and FBVBS.ABI.Memory_Permission_Write) = 0
           or else (Permissions and FBVBS.ABI.Memory_Permission_Execute) = 0);
   end Valid_Permissions;

   function Valid_VM_Map_State (State : FBVBS.ABI.Partition_State) return Boolean is
     (State = FBVBS.ABI.Created
      or else State = FBVBS.ABI.Measured
      or else State = FBVBS.ABI.Loaded
      or else State = FBVBS.ABI.Runnable
      or else State = FBVBS.ABI.Quiesced);

   procedure Initialize_Object (Object : out FBVBS.ABI.Memory_Object_Record) is
   begin
      Object :=
        (Allocated        => False,
         Object_Flags     => 0,
         Memory_Object_Id => 0,
         Size             => 0,
         Map_Count        => 0,
         Shared_Count     => 0);
   end Initialize_Object;

   procedure Allocate_Object
     (Object          : in out FBVBS.ABI.Memory_Object_Record;
      Next_Object_Id  : in out FBVBS.ABI.Handle;
      Size            : FBVBS.ABI.U64;
      Object_Flags    : FBVBS.ABI.U32;
      Status          : out FBVBS.ABI.Status_Code)
   is
   begin
      if Object.Allocated or else Size = 0 or else (Size mod FBVBS.ABI.Page_Size) /= 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Object_Flags /= FBVBS.ABI.Memory_Object_Flag_Private
        and then Object_Flags /= FBVBS.ABI.Memory_Object_Flag_Shareable
        and then Object_Flags /= FBVBS.ABI.Memory_Object_Flag_Guest_Memory
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Next_Object_Id = 0 then
         Status := FBVBS.ABI.Resource_Exhausted;
      else
         Object.Allocated := True;
         Object.Object_Flags := Object_Flags;
         Object.Memory_Object_Id := Next_Object_Id;
         Object.Size := Size;
         Object.Map_Count := 0;
         Object.Shared_Count := 0;
         Next_Object_Id := Next_Object_Id + 1;
         Status := FBVBS.ABI.OK;
      end if;
   end Allocate_Object;

   procedure Set_Permissions
     (Partition   : FBVBS.ABI.Partition_Descriptor;
      Permissions : FBVBS.ABI.U32;
      Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use then
         Status := FBVBS.ABI.Invalid_Caller;
      elsif not Has_All_Bits (Partition.Capability_Mask, FBVBS.ABI.Capability_Memory_Set_Permission) then
         Status := FBVBS.ABI.Permission_Denied;
      elsif not Valid_Permissions (Permissions) then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Set_Permissions;

   procedure Map_Object
      (Partition   : in out FBVBS.ABI.Partition_Descriptor;
       Object      : in out FBVBS.ABI.Memory_Object_Record;
       Memory_Object_Id : FBVBS.ABI.Handle;
       Guest_Physical_Address : FBVBS.ABI.U64;
       Size        : FBVBS.ABI.U64;
       Permissions : FBVBS.ABI.U32;
       Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif Partition.State = FBVBS.ABI.Running
        or else Partition.State = FBVBS.ABI.Faulted
        or else Partition.State = FBVBS.ABI.Destroyed
      then
         Status := FBVBS.ABI.Invalid_State;
      elsif not Has_All_Bits (Partition.Capability_Mask, FBVBS.ABI.Capability_Memory_Map) then
         Status := FBVBS.ABI.Permission_Denied;
      elsif Memory_Object_Id = 0
        or else Guest_Physical_Address = 0
        or else (Guest_Physical_Address mod FBVBS.ABI.Page_Size) /= 0
        or else Size = 0
        or else (Size mod FBVBS.ABI.Page_Size) /= 0
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Object.Allocated or else Memory_Object_Id /= Object.Memory_Object_Id then
         Status := FBVBS.ABI.Not_Found;
      elsif Size > Object.Size then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Valid_Permissions (Permissions) then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Partition.Mapped_Bytes + Size > Partition.Memory_Limit_Bytes then
         Status := FBVBS.ABI.Resource_Exhausted;
      else
         Partition.Mapped_Bytes := Partition.Mapped_Bytes + Size;
         Object.Map_Count := Object.Map_Count + 1;
         Status := FBVBS.ABI.OK;
      end if;
   end Map_Object;

   procedure Map_VM_Object
     (Partition   : in out FBVBS.ABI.Partition_Descriptor;
      Object      : in out FBVBS.ABI.Memory_Object_Record;
      Memory_Object_Id : FBVBS.ABI.Handle;
      Guest_Physical_Address : FBVBS.ABI.U64;
      Size        : FBVBS.ABI.U64;
      Permissions : FBVBS.ABI.U32;
      Status      : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use then
         Status := FBVBS.ABI.Not_Found;
      elsif Partition.Kind /= FBVBS.ABI.Partition_Guest_VM then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Valid_VM_Map_State (Partition.State) then
         Status := FBVBS.ABI.Invalid_State;
      elsif Memory_Object_Id = 0
        or else Guest_Physical_Address = 0
        or else (Guest_Physical_Address mod FBVBS.ABI.Page_Size) /= 0
        or else Size = 0
        or else (Size mod FBVBS.ABI.Page_Size) /= 0
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Object.Allocated or else Memory_Object_Id /= Object.Memory_Object_Id then
         Status := FBVBS.ABI.Not_Found;
      elsif Object.Object_Flags /= FBVBS.ABI.Memory_Object_Flag_Guest_Memory then
         Status := FBVBS.ABI.Permission_Denied;
      elsif Size > Object.Size then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Valid_Permissions (Permissions) then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Partition.Mapped_Bytes + Size > Partition.Memory_Limit_Bytes then
         Status := FBVBS.ABI.Resource_Exhausted;
      else
         Partition.Mapped_Bytes := Partition.Mapped_Bytes + Size;
         Object.Map_Count := Object.Map_Count + 1;
         Status := FBVBS.ABI.OK;
      end if;
   end Map_VM_Object;

    procedure Unmap_Object
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Object    : in out FBVBS.ABI.Memory_Object_Record;
       Size      : FBVBS.ABI.U64;
       Status    : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Partition.In_Use or else not Object.Allocated then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Object.Map_Count = 0 or else Size = 0 or else Size > Partition.Mapped_Bytes then
         Status := FBVBS.ABI.Invalid_State;
      else
         Partition.Mapped_Bytes := Partition.Mapped_Bytes - Size;
         Object.Map_Count := Object.Map_Count - 1;
         Status := FBVBS.ABI.OK;
      end if;
    end Unmap_Object;

   procedure Register_Sharing
     (Object            : in out FBVBS.ABI.Memory_Object_Record;
      Peer_Partition_Id : FBVBS.ABI.Handle;
      Permissions       : FBVBS.ABI.U32;
      Shared_Object_Id  : out FBVBS.ABI.Handle;
      Status            : out FBVBS.ABI.Status_Code)
   is
   begin
      Shared_Object_Id := 0;
      if not Object.Allocated then
         Status := FBVBS.ABI.Not_Found;
      elsif Object.Object_Flags /= FBVBS.ABI.Memory_Object_Flag_Shareable
        and then Object.Object_Flags /= FBVBS.ABI.Memory_Object_Flag_Guest_Memory
      then
         Status := FBVBS.ABI.Permission_Denied;
      elsif Peer_Partition_Id /= 0 and then Peer_Partition_Id = Object.Memory_Object_Id then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif not Valid_Permissions (Permissions) then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Object.Shared_Count := Object.Shared_Count + 1;
         Shared_Object_Id := Object.Memory_Object_Id;
         Status := FBVBS.ABI.OK;
      end if;
   end Register_Sharing;

   procedure Unregister_Sharing
     (Object  : in out FBVBS.ABI.Memory_Object_Record;
      Status  : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Object.Allocated then
         Status := FBVBS.ABI.Not_Found;
      elsif Object.Shared_Count = 0 then
         Status := FBVBS.ABI.Invalid_State;
      else
         Object.Shared_Count := Object.Shared_Count - 1;
         Status := FBVBS.ABI.OK;
      end if;
   end Unregister_Sharing;

    procedure Release_Object
      (Object : in out FBVBS.ABI.Memory_Object_Record;
       Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if not Object.Allocated then
         Status := FBVBS.ABI.Not_Found;
      elsif Object.Map_Count /= 0 or else Object.Shared_Count /= 0 then
         Status := FBVBS.ABI.Resource_Busy;
      else
         Initialize_Object (Object);
         Status := FBVBS.ABI.OK;
      end if;
   end Release_Object;
end FBVBS.Memory;
