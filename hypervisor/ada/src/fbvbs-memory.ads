with FBVBS.ABI;

package FBVBS.Memory
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Memory_Object_Record;
   use type FBVBS.ABI.Partition_State;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;

   procedure Initialize_Object (Object : out FBVBS.ABI.Memory_Object_Record)
     with Post => not Object.Allocated;

   procedure Allocate_Object
     (Object          : in out FBVBS.ABI.Memory_Object_Record;
      Next_Object_Id  : in out FBVBS.ABI.Handle;
      Size            : FBVBS.ABI.U64;
      Object_Flags    : FBVBS.ABI.U32;
      Status          : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             Object.Allocated
             and then Object.Size = Size
             and then Object.Object_Flags = Object_Flags
          else
             Object = Object'Old);

   procedure Set_Permissions
     (Partition   : FBVBS.ABI.Partition_Descriptor;
      Permissions : FBVBS.ABI.U32;
      Status      : out FBVBS.ABI.Status_Code);

   procedure Map_Object
      (Partition   : in out FBVBS.ABI.Partition_Descriptor;
       Object      : in out FBVBS.ABI.Memory_Object_Record;
       Memory_Object_Id : FBVBS.ABI.Handle;
       Guest_Physical_Address : FBVBS.ABI.U64;
       Size        : FBVBS.ABI.U64;
       Permissions : FBVBS.ABI.U32;
       Status      : out FBVBS.ABI.Status_Code);

   procedure Map_VM_Object
     (Partition   : in out FBVBS.ABI.Partition_Descriptor;
      Object      : in out FBVBS.ABI.Memory_Object_Record;
      Memory_Object_Id : FBVBS.ABI.Handle;
      Guest_Physical_Address : FBVBS.ABI.U64;
      Size        : FBVBS.ABI.U64;
      Permissions : FBVBS.ABI.U32;
      Status      : out FBVBS.ABI.Status_Code);

    procedure Unmap_Object
      (Partition : in out FBVBS.ABI.Partition_Descriptor;
       Object    : in out FBVBS.ABI.Memory_Object_Record;
       Size      : FBVBS.ABI.U64;
       Status    : out FBVBS.ABI.Status_Code);

   procedure Register_Sharing
     (Object            : in out FBVBS.ABI.Memory_Object_Record;
      Peer_Partition_Id : FBVBS.ABI.Handle;
      Permissions       : FBVBS.ABI.U32;
      Shared_Object_Id  : out FBVBS.ABI.Handle;
      Status            : out FBVBS.ABI.Status_Code);

   procedure Unregister_Sharing
     (Object  : in out FBVBS.ABI.Memory_Object_Record;
      Status  : out FBVBS.ABI.Status_Code);

    procedure Release_Object
      (Object : in out FBVBS.ABI.Memory_Object_Record;
       Status : out FBVBS.ABI.Status_Code);
end FBVBS.Memory;
