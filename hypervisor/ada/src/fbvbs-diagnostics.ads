with FBVBS.ABI;

package FBVBS.Diagnostics
  with SPARK_Mode
is
   procedure Get_Capabilities
     (Caps   : FBVBS.ABI.Platform_Capabilities;
      Result : out FBVBS.ABI.Diag_Capabilities_Record);

   procedure Describe_Partition
     (Partition : FBVBS.ABI.Partition_Descriptor;
      Result    : out FBVBS.ABI.Diag_Partition_Record);

   procedure Describe_Artifact
     (Artifact : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Result   : out FBVBS.ABI.Diag_Artifact_Record);

   procedure Describe_Device
     (Device_Id      : FBVBS.ABI.Handle;
      Segment        : FBVBS.ABI.U32;
      Bus            : FBVBS.ABI.U32;
      Slot_Function  : FBVBS.ABI.U32;
      Domain         : FBVBS.ABI.IOMMU_Domain_Record;
      Result         : out FBVBS.ABI.Diag_Device_Record);
end FBVBS.Diagnostics;
