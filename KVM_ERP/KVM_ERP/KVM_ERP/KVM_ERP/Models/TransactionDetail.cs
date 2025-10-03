using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace KVM_ERP.Models
{
    [Table("TRANSACTIONDETAIL")]
    public class TransactionDetail
    {
        [Key]
        [Column("TRANDID")]
        public int TRANDID { get; set; }

        [Required]
        [Column("TRANMID")]
        public int TRANMID { get; set; }

        [Required]
        [Column("MTRLGID")]
        public int MTRLGID { get; set; }

        [Required]
        [Column("MTRLID")]
        public int MTRLID { get; set; }

        [Required]
        [Column("MTRLNBOX")]
        public int MTRLNBOX { get; set; }

        [Required]
        [Column("MTRLCOUNTS")]
        public int MTRLCOUNTS { get; set; }

        [Required]
        [MaxLength(100)]
        [Column("CUSRID")]
        public string CUSRID { get; set; }

        [Required]
        [MaxLength(100)]
        [Column("LMUSRID")]
        public string LMUSRID { get; set; }

        [Required]
        [Column("DISPSTATUS")]
        public short DISPSTATUS { get; set; }

        [Required]
        [Column("PRCSDATE")]
        public DateTime PRCSDATE { get; set; }
    }
}
