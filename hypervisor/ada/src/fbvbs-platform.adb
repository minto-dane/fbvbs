with FBVBS.ABI;

package body FBVBS.Platform
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.U32;

   procedure Initialize
     (Caps   : out FBVBS.ABI.Platform_Capabilities;
      Domain : out FBVBS.ABI.IOMMU_Domain_Record)
   is
   begin
      Caps := (Has_HLAT => False, Has_IOMMU => False);
      Domain :=
        (In_Use                => False,
         Domain_Id             => 0,
         Owner_Partition_Id    => 0,
         Attached_Device_Count => 0);
   end Initialize;

   procedure Configure
     (Caps      : in out FBVBS.ABI.Platform_Capabilities;
      Has_HLAT  : Boolean;
      Has_IOMMU : Boolean)
   is
   begin
      Caps.Has_HLAT := Has_HLAT;
      Caps.Has_IOMMU := Has_IOMMU;
   end Configure;

   procedure Check_VM_Create
     (Caps   : FBVBS.ABI.Platform_Capabilities;
      Status : out FBVBS.ABI.Status_Code)
   is
   begin
      if Caps.Has_HLAT then
         Status := FBVBS.ABI.OK;
      else
         Status := FBVBS.ABI.Not_Supported_On_Platform;
      end if;
   end Check_VM_Create;

   procedure Attach_Device
     (Caps           : FBVBS.ABI.Platform_Capabilities;
      Partition_Id   : FBVBS.ABI.Handle;
      Next_Domain_Id : in out FBVBS.ABI.Handle;
      Device_Id      : FBVBS.ABI.Handle;
      Domain         : in out FBVBS.ABI.IOMMU_Domain_Record;
      Status         : out FBVBS.ABI.Status_Code)
   is
      pragma Unreferenced (Device_Id);
   begin
      if not Caps.Has_IOMMU then
         Status := FBVBS.ABI.Not_Supported_On_Platform;
      elsif Domain.In_Use and then Domain.Owner_Partition_Id /= Partition_Id then
         Status := FBVBS.ABI.Internal_Corruption;
      else
         if not Domain.In_Use then
            Domain.In_Use := True;
            Domain.Domain_Id := Next_Domain_Id;
            Domain.Owner_Partition_Id := Partition_Id;
            Domain.Attached_Device_Count := 0;
            Next_Domain_Id := Next_Domain_Id + 1;
         end if;
         Domain.Attached_Device_Count := Domain.Attached_Device_Count + 1;
         Status := FBVBS.ABI.OK;
      end if;
   end Attach_Device;

   procedure Release_Device
     (Partition_Id : FBVBS.ABI.Handle;
      Device_Id    : FBVBS.ABI.Handle;
      Domain       : in out FBVBS.ABI.IOMMU_Domain_Record;
      Status       : out FBVBS.ABI.Status_Code)
   is
      pragma Unreferenced (Device_Id);
   begin
      if not Domain.In_Use then
         Status := FBVBS.ABI.Invalid_State;
      elsif Domain.Owner_Partition_Id /= Partition_Id or else Domain.Attached_Device_Count = 0 then
         Status := FBVBS.ABI.Internal_Corruption;
      else
         Domain.Attached_Device_Count := Domain.Attached_Device_Count - 1;
         if Domain.Attached_Device_Count = 0 then
            Domain.In_Use := False;
            Domain.Domain_Id := 0;
            Domain.Owner_Partition_Id := 0;
         end if;
         Status := FBVBS.ABI.OK;
      end if;
   end Release_Device;
end FBVBS.Platform;
