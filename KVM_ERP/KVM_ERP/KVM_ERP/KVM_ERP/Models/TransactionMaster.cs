using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace KVM_ERP.Models
{
    [Table("TRANSACTIONMASTER")]
    public class TransactionMaster
    {
        [Key]
        [Column("TRANMID")]
        public int TRANMID { get; set; }

        [Required]
        [Column("TRANDATE")]
        public DateTime TRANDATE { get; set; }

        [Required]
        [MaxLength(100)]
        [Column("CATENAME")]
        public string CATENAME { get; set; }

        [Required]
        [MaxLength(50)]
        [Column("CATECODE")]
        public string CATECODE { get; set; }

        [Required]
        [MaxLength(50)]
        [Column("VECHNO")]
        public string VECHNO { get; set; }

        [Required]
        [Column("DISPSTATUS")]
        public short DISPSTATUS { get; set; }

        [Required]
        [MaxLength(100)]
        [Column("CUSRID")]
        public string CUSRID { get; set; }

        [Required]
        [MaxLength(100)]
        [Column("LMUSRID")]
        public string LMUSRID { get; set; }

        [Required]
        [Column("PRCSDATE")]
        public DateTime PRCSDATE { get; set; }
    }
}
