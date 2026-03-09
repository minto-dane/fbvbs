with FBVBS.ABI;

package FBVBS.Platform
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.IOMMU_Domain_Record;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;

   procedure Initialize
     (Caps   : out FBVBS.ABI.Platform_Capabilities;
      Domain : out FBVBS.ABI.IOMMU_Domain_Record)
     with
       Post =>
         (not Caps.Has_HLAT and then
          not Caps.Has_IOMMU and then
          not Domain.In_Use);

   procedure Configure
     (Caps      : in out FBVBS.ABI.Platform_Capabilities;
      Has_HLAT  : Boolean;
      Has_IOMMU : Boolean)
     with
       Post =>
         Caps.Has_HLAT = Has_HLAT and then
         Caps.Has_IOMMU = Has_IOMMU;

   procedure Check_VM_Create
     (Caps   : FBVBS.ABI.Platform_Capabilities;
      Status : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Caps.Has_HLAT then
             Status = FBVBS.ABI.OK
          else
             Status = FBVBS.ABI.Not_Supported_On_Platform);

   procedure Attach_Device
     (Caps          : FBVBS.ABI.Platform_Capabilities;
      Partition_Id  : FBVBS.ABI.Handle;
      Next_Domain_Id : in out FBVBS.ABI.Handle;
      Device_Id     : FBVBS.ABI.Handle;
      Domain        : in out FBVBS.ABI.IOMMU_Domain_Record;
      Status        : out FBVBS.ABI.Status_Code)
     with
       Pre => Device_Id /= 0 and then Partition_Id /= 0,
       Post =>
         (if Status = FBVBS.ABI.OK then
             Domain.In_Use and then
             Domain.Owner_Partition_Id = Partition_Id and then
             Domain.Attached_Device_Count >= 1
          else
             Domain = Domain'Old);

   procedure Release_Device
     (Partition_Id : FBVBS.ABI.Handle;
      Device_Id    : FBVBS.ABI.Handle;
      Domain       : in out FBVBS.ABI.IOMMU_Domain_Record;
      Status       : out FBVBS.ABI.Status_Code)
     with
       Pre => Partition_Id /= 0 and then Device_Id /= 0,
       Post =>
         (if Status = FBVBS.ABI.OK and then Domain.Attached_Device_Count = 0 then
             not Domain.In_Use
          elsif Status = FBVBS.ABI.OK then
             Domain.In_Use
          else
             Domain = Domain'Old);
end FBVBS.Platform;
