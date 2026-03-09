with FBVBS.ABI;

package FBVBS.Boot
  with SPARK_Mode
is
   use type FBVBS.ABI.Artifact_Object_Kind;
   use type FBVBS.ABI.Manifest_Component_Type;
   use type FBVBS.ABI.Host_Caller_Class;
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.U32;
   use type FBVBS.ABI.U64;

   procedure Validate_Catalog_Pair
     (Artifact_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Artifact_Index : FBVBS.ABI.U32;
      Manifest_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Manifest_Index : FBVBS.ABI.U32;
      Status         : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
              Artifact_Entry.Object_Id /= 0
              and then Manifest_Entry.Object_Id /= 0
              and then Manifest_Entry.Object_Kind = FBVBS.ABI.Artifact_Manifest
              and then Artifact_Entry.Related_Index = Manifest_Index
              and then Manifest_Entry.Related_Index = Artifact_Index);

   procedure Validate_Profile_Binding
     (Profile        : FBVBS.ABI.Manifest_Profile_Record;
      Artifact_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Manifest_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Status         : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
              Profile.Object_Id = Artifact_Entry.Object_Id
              and then Profile.Manifest_Object_Id = Manifest_Entry.Object_Id);

   procedure Validate_Host_Profile
     (Profile        : FBVBS.ABI.Host_Callsite_Profile_Record;
      Artifact_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Manifest_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Status         : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
              Profile.Object_Id = Artifact_Entry.Object_Id
              and then Profile.Manifest_Object_Id = Manifest_Entry.Object_Id
              and then Profile.Load_Base /= 0);
end FBVBS.Boot;
