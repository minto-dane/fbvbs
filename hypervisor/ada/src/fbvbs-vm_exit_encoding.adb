with FBVBS.ABI;

package body FBVBS.VM_Exit_Encoding
  with SPARK_Mode
is
   function Exit_Code (Reason : FBVBS.ABI.VM_Exit_Reason) return FBVBS.ABI.U32 is
   begin
      case Reason is
         when FBVBS.ABI.No_Exit =>
            return 0;
         when FBVBS.ABI.Exit_PIO =>
            return 1;
         when FBVBS.ABI.Exit_MMIO =>
            return 2;
         when FBVBS.ABI.Exit_External_Interrupt =>
            return 3;
         when FBVBS.ABI.Exit_EPT_Violation =>
            return 4;
         when FBVBS.ABI.Exit_CR_Access =>
            return 5;
         when FBVBS.ABI.Exit_MSR_Access =>
            return 6;
         when FBVBS.ABI.Exit_Halt =>
            return 7;
         when FBVBS.ABI.Exit_Shutdown =>
            return 8;
         when FBVBS.ABI.Exit_Unclassified_Fault =>
            return 9;
      end case;
   end Exit_Code;

   function Payload_Length (Reason : FBVBS.ABI.VM_Exit_Reason) return FBVBS.ABI.U32 is
   begin
      case Reason is
         when FBVBS.ABI.No_Exit | FBVBS.ABI.Exit_Halt | FBVBS.ABI.Exit_Shutdown =>
            return 0;
         when FBVBS.ABI.Exit_External_Interrupt | FBVBS.ABI.Exit_PIO =>
            return 8;
         when FBVBS.ABI.Exit_MMIO
           | FBVBS.ABI.Exit_CR_Access
           | FBVBS.ABI.Exit_MSR_Access
           | FBVBS.ABI.Exit_EPT_Violation =>
            return 16;
         when FBVBS.ABI.Exit_Unclassified_Fault =>
            return 24;
      end case;
   end Payload_Length;
end FBVBS.VM_Exit_Encoding;
