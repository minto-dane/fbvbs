with FBVBS.ABI;

package body FBVBS.Boot
  with SPARK_Mode
is
   use type FBVBS.ABI.Trusted_Service_Kind;

   procedure Validate_Catalog_Pair
     (Artifact_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Artifact_Index : FBVBS.ABI.U32;
      Manifest_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Manifest_Index : FBVBS.ABI.U32;
      Status         : out FBVBS.ABI.Status_Code)
   is
   begin
      if Artifact_Entry.Object_Id = 0 or else Manifest_Entry.Object_Id = 0 then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif (Artifact_Entry.Object_Kind /= FBVBS.ABI.Artifact_Image and then
             Artifact_Entry.Object_Kind /= FBVBS.ABI.Artifact_Module) or else
        Manifest_Entry.Object_Kind /= FBVBS.ABI.Artifact_Manifest
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Artifact_Entry.Related_Index /= Manifest_Index or else
        Manifest_Entry.Related_Index /= Artifact_Index
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Validate_Catalog_Pair;

   procedure Validate_Profile_Binding
     (Profile        : FBVBS.ABI.Manifest_Profile_Record;
      Artifact_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Manifest_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Status         : out FBVBS.ABI.Status_Code)
   is
   begin
      if Profile.Object_Id /= Artifact_Entry.Object_Id or else
        Profile.Manifest_Object_Id /= Manifest_Entry.Object_Id
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Profile.Component_Type = FBVBS.ABI.Manifest_Trusted_Service then
         if Artifact_Entry.Object_Kind /= FBVBS.ABI.Artifact_Image or else
           Profile.Service_Kind = FBVBS.ABI.Service_None or else
           Profile.VCPU_Count = 0 or else
           Profile.Memory_Limit_Bytes = 0 or else
           Profile.Entry_IP = 0 or else
           Profile.Initial_SP = 0
         then
            Status := FBVBS.ABI.Invalid_Parameter;
         else
            Status := FBVBS.ABI.OK;
         end if;
      elsif Profile.Component_Type = FBVBS.ABI.Manifest_Guest_Boot then
         if Artifact_Entry.Object_Kind /= FBVBS.ABI.Artifact_Image or else
           Profile.Entry_IP = 0
         then
            Status := FBVBS.ABI.Invalid_Parameter;
         else
            Status := FBVBS.ABI.OK;
         end if;
      else
         Status := FBVBS.ABI.Invalid_Parameter;
      end if;
   end Validate_Profile_Binding;

   procedure Validate_Host_Profile
     (Profile        : FBVBS.ABI.Host_Callsite_Profile_Record;
      Artifact_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Manifest_Entry : FBVBS.ABI.Artifact_Catalog_Entry_Record;
      Status         : out FBVBS.ABI.Status_Code)
   is
   begin
      if Profile.Object_Id /= Artifact_Entry.Object_Id or else
        Profile.Manifest_Object_Id /= Manifest_Entry.Object_Id
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif Manifest_Entry.Object_Kind /= FBVBS.ABI.Artifact_Manifest or else
        Profile.Load_Base = 0 or else
        Profile.Primary_Offset = 0 or else
        Profile.Secondary_Offset = 0
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      elsif (Profile.Caller_Class = FBVBS.ABI.Host_Caller_FBVBS and then
             Artifact_Entry.Object_Kind /= FBVBS.ABI.Artifact_Image) or else
        (Profile.Caller_Class = FBVBS.ABI.Host_Caller_VMM and then
           Artifact_Entry.Object_Kind /= FBVBS.ABI.Artifact_Module) or else
        Profile.Caller_Class = FBVBS.ABI.Host_Caller_None
      then
         Status := FBVBS.ABI.Invalid_Parameter;
      else
         Status := FBVBS.ABI.OK;
      end if;
   end Validate_Host_Profile;
end FBVBS.Boot;
