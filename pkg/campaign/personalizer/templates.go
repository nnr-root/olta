package personalizer

// Category identifies one of the built-in scenario collections.
type Category string

const (
	StudentScenarioCategory   Category = "student_scenarios"
	GeneralHRScenarioCategory Category = "general_hr_scenarios"
	FinanceScenarioCategory   Category = "finance_scenarios"
	ITScenarioCategory        Category = "it_scenarios"
)

// ScenarioTemplate is a coherent subject/body combination. A scenario is
// selected once per recipient, so its subject and content always stay paired.
type ScenarioTemplate struct {
	ID       string
	Name     string
	Category Category
	Variant  string
	Subject  string
	Text     string
	HTML     string
}

// StudentScenarios contains financial-aid and student-portal simulations.
var StudentScenarios = []ScenarioTemplate{
	{
		ID: "student-financial-aid-a", Name: "Burs / Financial Aid Approval", Category: StudentScenarioCategory, Variant: "A",
		Subject: "{Burs başvurunuz onaylandı|Mali yardım başvurunuz sonuçlandı}",
		Text:    "{Merhaba|Sayın} {{.FirstName}},\n\n{{.Company}} burs değerlendirmeniz onaylandı. Ödeme bilgilerinizi {{.PhishingURL}} adresinden {kontrol edin|doğrulayın}.\n\nÖğrenci İşleri",
		HTML:    "<p>{Merhaba|Sayın} {{.FirstName}},</p><p>{{.Company}} burs değerlendirmeniz onaylandı. Ödeme bilgilerinizi <a href=\"{{.PhishingURL}}\">{kontrol edin|doğrulayın}</a>.</p><p>Öğrenci İşleri</p>",
	},
	{
		ID: "student-financial-aid-b", Name: "Burs / Financial Aid Approval", Category: StudentScenarioCategory, Variant: "B",
		Subject: "{Burs ödeme planınız hazır|Öğrenci destek ödemeniz tanımlandı}",
		Text:    "{Sevgili|Merhaba} {{.FirstName}},\n\nBurs ödeme planınız hazırlandı. Son tarihi kaçırmadan {{.PhishingURL}} üzerinden hesap bilgilerinizi {gözden geçirin|tamamlayın}.\n\n{{.Company}} Mali Destek Birimi",
		HTML:    "<p>{Sevgili|Merhaba} {{.FirstName}},</p><p>Burs ödeme planınız hazırlandı. Son tarihi kaçırmadan <a href=\"{{.PhishingURL}}\">hesap bilgilerinizi {gözden geçirin|tamamlayın}</a>.</p><p>{{.Company}} Mali Destek Birimi</p>",
	},
	{
		ID: "student-portal-reset-a", Name: "ÖBS / Portal Security Breach & Password Reset", Category: StudentScenarioCategory, Variant: "A",
		Subject: "{ÖBS güvenlik bildirimi|Öğrenci portalı parola sıfırlama gerekiyor}",
		Text:    "{Merhaba|Sayın} {{.FirstName}},\n\nÖBS hesabınızla ilişkili şüpheli bir oturum tespit edildi. Erişiminizi korumak için {{.PhishingURL}} bağlantısından parolanızı {yenileyin|sıfırlayın}.\n\n{{.Company}} Bilgi İşlem",
		HTML:    "<p>{Merhaba|Sayın} {{.FirstName}},</p><p>ÖBS hesabınızla ilişkili şüpheli bir oturum tespit edildi. Erişiminizi korumak için <a href=\"{{.PhishingURL}}\">parolanızı {yenileyin|sıfırlayın}</a>.</p><p>{{.Company}} Bilgi İşlem</p>",
	},
	{
		ID: "student-portal-reset-b", Name: "ÖBS / Portal Security Breach & Password Reset", Category: StudentScenarioCategory, Variant: "B",
		Subject: "{ÖBS oturumunuz askıya alındı|Portal hesabınız için güvenlik doğrulaması}",
		Text:    "{Merhaba|İyi günler} {{.FirstName}},\n\nÖğrenci portalındaki güvenlik güncellemesi nedeniyle oturumunuz askıya alındı. {{.PhishingURL}} adresinden kimliğinizi {doğrulayın|yeniden etkinleştirin}.\n\nDestek Ekibi",
		HTML:    "<p>{Merhaba|İyi günler} {{.FirstName}},</p><p>Öğrenci portalındaki güvenlik güncellemesi nedeniyle oturumunuz askıya alındı. <a href=\"{{.PhishingURL}}\">Kimliğinizi {doğrulayın|yeniden etkinleştirin}</a>.</p><p>Destek Ekibi</p>",
	},
}

// GeneralHRScenarios contains annual-leave and recognition simulations.
var GeneralHRScenarios = []ScenarioTemplate{
	{
		ID: "hr-leave-a", Name: "Unused Annual Leave Warning", Category: GeneralHRScenarioCategory, Variant: "A",
		Subject: "{Kullanılmayan izin bakiyeniz|Yıllık izin bakiyesi bildirimi}",
		Text:    "{Merhaba|Sayın} {{.FirstName}},\n\n{{.Department}} kayıtlarında kullanılmayan yıllık izniniz bulunuyor. Bakiyenizi {{.PhishingURL}} üzerinden {inceleyin|planlayın}.\n\n{{.ManagerName}}\nİnsan Kaynakları",
		HTML:    "<p>{Merhaba|Sayın} {{.FirstName}},</p><p>{{.Department}} kayıtlarında kullanılmayan yıllık izniniz bulunuyor. Bakiyenizi <a href=\"{{.PhishingURL}}\">{inceleyin|planlayın}</a>.</p><p>{{.ManagerName}}<br>İnsan Kaynakları</p>",
	},
	{
		ID: "hr-leave-b", Name: "Unused Annual Leave Warning", Category: GeneralHRScenarioCategory, Variant: "B",
		Subject: "{İzin günleriniz için son planlama hatırlatması|Yıllık izin hakedişiniz sona ermeden işlem yapın}",
		Text:    "{Merhaba|İyi günler} {{.FirstName}},\n\nDönem sonunda devredilemeyecek izin günleriniz olabilir. {{.PhishingURL}} bağlantısından güncel kaydı {onaylayın|görüntüleyin}.\n\n{{.Company}} İK",
		HTML:    "<p>{Merhaba|İyi günler} {{.FirstName}},</p><p>Dönem sonunda devredilemeyecek izin günleriniz olabilir. <a href=\"{{.PhishingURL}}\">Güncel kaydı {onaylayın|görüntüleyin}</a>.</p><p>{{.Company}} İK</p>",
	},
	{
		ID: "hr-reward-a", Name: "Performance Gift Card / Bonus Voucher", Category: GeneralHRScenarioCategory, Variant: "A",
		Subject: "{Performans ödülünüz hazır|Size özel başarı kuponu}",
		Text:    "{Tebrikler|Merhaba} {{.FirstName}},\n\n{{.Position}} rolündeki katkılarınız için bir ödül kuponu tanımlandı. {{.PhishingURL}} üzerinden {teslim alın|kuponu görüntüleyin}.\n\n{{.Company}} İnsan Kaynakları",
		HTML:    "<p>{Tebrikler|Merhaba} {{.FirstName}},</p><p>{{.Position}} rolündeki katkılarınız için bir ödül kuponu tanımlandı. <a href=\"{{.PhishingURL}}\">{Teslim alın|Kuponu görüntüleyin}</a>.</p><p>{{.Company}} İnsan Kaynakları</p>",
	},
	{
		ID: "hr-reward-b", Name: "Performance Gift Card / Bonus Voucher", Category: GeneralHRScenarioCategory, Variant: "B",
		Subject: "{Bonus hediye kartı bildirimi|Çalışan takdir ödülünüz}",
		Text:    "{Sayın|Merhaba} {{.FirstName}} {{.LastName}},\n\nDönemsel başarı programı kapsamında adınıza hediye kartı oluşturuldu. Son kullanma tarihinden önce {{.PhishingURL}} adresinden {etkinleştirin|talep edin}.\n\nİK Ekibi",
		HTML:    "<p>{Sayın|Merhaba} {{.FirstName}} {{.LastName}},</p><p>Dönemsel başarı programı kapsamında adınıza hediye kartı oluşturuldu. Son kullanma tarihinden önce <a href=\"{{.PhishingURL}}\">{etkinleştirin|talep edin}</a>.</p><p>İK Ekibi</p>",
	},
}

// FinanceScenarios contains supplier-payment and e-invoice simulations.
var FinanceScenarios = []ScenarioTemplate{
	{
		ID: "finance-invoice-a", Name: "Urgent Overdue e-Invoice / Supplier Payment", Category: FinanceScenarioCategory, Variant: "A",
		Subject: "{Acil: vadesi geçen e-Fatura|Tedarikçi ödemesi onay bekliyor}",
		Text:    "{Merhaba|Sayın} {{.FirstName}},\n\n{{.Department}} birimine atanan vadesi geçmiş e-Fatura için işlem gerekiyor. Kaydı {{.PhishingURL}} üzerinden {inceleyin|onaylayın}.\n\n{{.Company}} Finans Operasyonları",
		HTML:    "<p>{Merhaba|Sayın} {{.FirstName}},</p><p>{{.Department}} birimine atanan vadesi geçmiş e-Fatura için işlem gerekiyor. Kaydı <a href=\"{{.PhishingURL}}\">{inceleyin|onaylayın}</a>.</p><p>{{.Company}} Finans Operasyonları</p>",
	},
	{
		ID: "finance-invoice-b", Name: "Urgent Overdue e-Invoice / Supplier Payment", Category: FinanceScenarioCategory, Variant: "B",
		Subject: "{Ödeme gecikmesi: tedarikçi hesabı|Bekleyen fatura mutabakatı}",
		Text:    "{İyi günler|Merhaba} {{.FirstName}},\n\nTedarikçi hesabında mutabakat bekleyen bir ödeme tespit edildi. Ayrıntıları {{.PhishingURL}} adresinden {doğrulayın|kontrol edin}.\n\nMuhasebe Operasyonları",
		HTML:    "<p>{İyi günler|Merhaba} {{.FirstName}},</p><p>Tedarikçi hesabında mutabakat bekleyen bir ödeme tespit edildi. Ayrıntıları <a href=\"{{.PhishingURL}}\">{doğrulayın|kontrol edin}</a>.</p><p>Muhasebe Operasyonları</p>",
	},
}

// ITScenarios contains source-control token-expiration simulations.
var ITScenarios = []ScenarioTemplate{
	{
		ID: "it-token-a", Name: "GitHub / GitLab Access Token Expiration", Category: ITScenarioCategory, Variant: "A",
		Subject: "{GitHub erişim anahtarınızın süresi doluyor|GitLab token yenileme bildirimi}",
		Text:    "{Merhaba|Sayın} {{.FirstName}},\n\n{{.Department}} hesabınıza bağlı erişim anahtarının süresi yakında dolacak. Kesintiyi önlemek için {{.PhishingURL}} üzerinden anahtarı {yenileyin|gözden geçirin}.\n\n{{.Company}} Platform Ekibi",
		HTML:    "<p>{Merhaba|Sayın} {{.FirstName}},</p><p>{{.Department}} hesabınıza bağlı erişim anahtarının süresi yakında dolacak. Kesintiyi önlemek için <a href=\"{{.PhishingURL}}\">anahtarı {yenileyin|gözden geçirin}</a>.</p><p>{{.Company}} Platform Ekibi</p>",
	},
	{
		ID: "it-token-b", Name: "GitHub / GitLab Access Token Expiration", Category: ITScenarioCategory, Variant: "B",
		Subject: "{Depo erişiminiz için işlem gerekiyor|Kaynak kodu erişim tokenı sona erdi}",
		Text:    "{Merhaba|İyi günler} {{.FirstName}},\n\n{{.Position}} hesabınızın kaynak kodu erişim tokenı sona erdi. Erişimi tekrar etkinleştirmek için {{.PhishingURL}} adresinden {doğrulama yapın|yeni token oluşturun}.\n\nDevOps Destek",
		HTML:    "<p>{Merhaba|İyi günler} {{.FirstName}},</p><p>{{.Position}} hesabınızın kaynak kodu erişim tokenı sona erdi. Erişimi tekrar etkinleştirmek için <a href=\"{{.PhishingURL}}\">{doğrulama yapın|yeni token oluşturun}</a>.</p><p>DevOps Destek</p>",
	},
}

var builtInScenarios = map[Category][]ScenarioTemplate{
	StudentScenarioCategory:   append([]ScenarioTemplate(nil), StudentScenarios...),
	GeneralHRScenarioCategory: append([]ScenarioTemplate(nil), GeneralHRScenarios...),
	FinanceScenarioCategory:   append([]ScenarioTemplate(nil), FinanceScenarios...),
	ITScenarioCategory:        append([]ScenarioTemplate(nil), ITScenarios...),
}

// Scenarios returns a copy of the templates registered for category.
func Scenarios(category Category) []ScenarioTemplate {
	templates := builtInScenarios[category]
	return append([]ScenarioTemplate(nil), templates...)
}

// AllScenarios returns a copy of the complete built-in library.
func AllScenarios() map[Category][]ScenarioTemplate {
	result := make(map[Category][]ScenarioTemplate, len(builtInScenarios))
	for category := range builtInScenarios {
		result[category] = Scenarios(category)
	}
	return result
}
