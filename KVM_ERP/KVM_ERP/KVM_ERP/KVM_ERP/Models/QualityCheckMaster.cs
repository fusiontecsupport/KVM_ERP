using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Web.Mvc;

namespace KVM_ERP.Models
{
    [Table("QUALITYCHECKMASTER")]
    public class QualityCheckMaster
    {
        [Key]
        public int QUALIID { get; set; }

        [DisplayName("Quality Check Description")]
        [Required(ErrorMessage = "Please enter quality check description")]
        [MaxLength(100)]
        [Remote("ValidateQUALIDESC", "Common", AdditionalFields = "i_QUALIDESC", ErrorMessage = "This quality check description is already used.")]
        public string QUALIDESC { get; set; }

        [DisplayName("Quality Check Code")]
        [Required(ErrorMessage = "Please enter quality check code")]
        [MaxLength(50)]
        [Remote("ValidateQUALICODE", "Common", AdditionalFields = "i_QUALICODE", ErrorMessage = "This quality check code is already used.")]
        public string QUALICODE { get; set; }

        // Created user id (username)
        public string CUSRID { get; set; }

        // Last modified user id (username)
        public string LMUSRID { get; set; }

        [DisplayName("Status")]
        public short DISPSTATUS { get; set; }

        [DataType(DataType.Date)]
        public DateTime PRCSDATE { get; set; }
    }
}
