with FBVBS.ABI;

package FBVBS.VM_Exit_Encoding
  with SPARK_Mode
is
   function Exit_Code (Reason : FBVBS.ABI.VM_Exit_Reason) return FBVBS.ABI.U32;
   function Payload_Length (Reason : FBVBS.ABI.VM_Exit_Reason) return FBVBS.ABI.U32;
   function CR_Access_Type return FBVBS.ABI.U32 is (1);
   function MSR_Access_Type return FBVBS.ABI.U32 is (1);
   function EPT_Access_Type return FBVBS.ABI.U32 is (16#4#);
end FBVBS.VM_Exit_Encoding;
