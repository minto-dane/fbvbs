with FBVBS.ABI;

package FBVBS.KSI
  with SPARK_Mode
is
   use type FBVBS.ABI.Handle;
   use type FBVBS.ABI.Status_Code;
   use type FBVBS.ABI.Target_Count_Type;
   use type FBVBS.ABI.Target_Set_Record;

   procedure Initialize (State : out FBVBS.ABI.Target_Set_Record)
     with Post => not State.In_Use;

   procedure Create_Target_Set
     (State                   : in out FBVBS.ABI.Target_Set_Record;
      Target_Set_Id           : FBVBS.ABI.Handle;
      First_Target_Object_Id  : FBVBS.ABI.Handle;
      Second_Target_Object_Id : FBVBS.ABI.Handle;
      Target_Count            : FBVBS.ABI.Target_Count_Type;
      Status                  : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
             State.In_Use
             and then State.Target_Set_Id = Target_Set_Id
             and then State.Target_Count = Target_Count
          else
             State = State'Old);

   procedure Register_Target_Object
      (State     : in out FBVBS.ABI.Target_Set_Record;
       Object_Id : FBVBS.ABI.Handle;
       Guest_Physical_Address : FBVBS.ABI.U64;
       Size      : FBVBS.ABI.U64;
       Status    : out FBVBS.ABI.Status_Code)
      with
        Post =>
          (if Status = FBVBS.ABI.OK then
              State.In_Use
           else
              State = State'Old);

   procedure Register_Tier_B_Object
     (State     : in out FBVBS.ABI.Target_Set_Record;
      Object_Id : FBVBS.ABI.Handle;
      Guest_Physical_Address : FBVBS.ABI.U64;
      Size      : FBVBS.ABI.U64;
      Protection_Class : FBVBS.ABI.U32;
      Status    : out FBVBS.ABI.Status_Code)
     with
       Post =>
          (if Status = FBVBS.ABI.OK then
              State.In_Use
           else
              State = State'Old);

   procedure Modify_Tier_B_Object
     (State        : FBVBS.ABI.Target_Set_Record;
      Object_Id    : FBVBS.ABI.Handle;
      Patch_Length : FBVBS.ABI.U32;
      Status       : out FBVBS.ABI.Status_Code)
     with Post => True;

   procedure Register_Pointer
      (State             : in out FBVBS.ABI.Target_Set_Record;
       Pointer_Object_Id : FBVBS.ABI.Handle;
       Status            : out FBVBS.ABI.Status_Code)
     with
       Post =>
          (if Status = FBVBS.ABI.OK then
              State.Pointer_Object_Id = Pointer_Object_Id
           else
              State = State'Old);

   procedure Allocate_Ucred
     (State                  : in out FBVBS.ABI.Target_Set_Record;
      Requested_UID          : FBVBS.ABI.U32;
      Requested_GID          : FBVBS.ABI.U32;
      Prison_Object_Id       : FBVBS.ABI.Handle;
      Template_Ucred_Object_Id : FBVBS.ABI.Handle;
      Ucred_Object_Id        : out FBVBS.ABI.Handle;
      Status                 : out FBVBS.ABI.Status_Code)
     with Post => True;

     procedure Replace_Tier_B_Object
       (State         : in out FBVBS.ABI.Target_Set_Record;
        New_Object_Id : FBVBS.ABI.Handle;
        Status        : out FBVBS.ABI.Status_Code)
     with
       Post =>
         (if Status = FBVBS.ABI.OK then
              State.Replacement_Object_Id = New_Object_Id
           else
              State = State'Old);

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
      with Post => True;

   procedure Unregister_Object
     (State     : in out FBVBS.ABI.Target_Set_Record;
      Object_Id : FBVBS.ABI.Handle;
      Status    : out FBVBS.ABI.Status_Code)
     with Post => True;
end FBVBS.KSI;
