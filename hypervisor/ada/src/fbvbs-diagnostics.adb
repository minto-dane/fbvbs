with FBVBS.ABI;

package body FBVBS.Diagnostics
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;

   procedure Get_Capabilities
     (Caps   : FBVBS.ABI.Platform_Capabilities;
      Result : out FBVBS.ABI.Diag_Capabilities_Record)
   is
   begin
      Result :=
        (Capability_Bitmap0 =>
           (if Caps.Has_HLAT then FBVBS.ABI.Cap_Bitmap0_HLAT else 0),
         Capability_Bitmap1 =>
           (if Caps.Has_IOMMU then FBVBS.ABI.Cap_Bitmap1_IOMMU else 0));
   end Get_Capabilities;

   procedure Describe_Partition
     (Partition : FBVBS.ABI.Partition_Descriptor;
      Result    : out FBVBS.ABI.Diag_Partition_Record)
   is
   begin
      Result :=
        (Count        => (if Partition.In_Use then 1 else 0),
         Partition_Id => Partition.Partition_Id,
         State        => Partition.State,
         Kind         => Partition.Kind,
         Service_Kind => Partition.Service_Kind);
   end Describe_Partition;

   procedure Describe_Artifact
     (Artifact : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Result   : out FBVBS.ABI.Diag_Artifact_Record)
   is
   begin
      Result :=
        (Count         => (if Artifact.Object_Id /= 0 then 1 else 0),
         Object_Id     => Artifact.Object_Id,
         Object_Kind   => Artifact.Object_Kind,
         Related_Index => Artifact.Related_Index);
   end Describe_Artifact;

   procedure Describe_Device
     (Device_Id      : FBVBS.ABI.Handle;
      Segment        : FBVBS.ABI.U32;
      Bus            : FBVBS.ABI.U32;
      Slot_Function  : FBVBS.ABI.U32;
      Domain         : FBVBS.ABI.IOMMU_Domain_Record;
      Result         : out FBVBS.ABI.Diag_Device_Record)
   is
   begin
      Result :=
        (Count         => (if Domain.In_Use and then Device_Id /= 0 then 1 else 0),
         Device_Id     => Device_Id,
         Segment       => Segment,
         Bus           => Bus,
         Slot_Function => Slot_Function);
   end Describe_Device;
end FBVBS.Diagnostics;
