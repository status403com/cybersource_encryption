package cybersource

import (
	"fmt"
	"strings"
)

func DetermineCardType(cardNumber string) CardType {
	cardNumber = strings.ReplaceAll(cardNumber, " ", "")
	cardNumber = strings.ReplaceAll(cardNumber, "-", "")

	if len(cardNumber) < 4 {
		return "000"
	}

	// Check prefixes (order matters for some overlapping ranges)

	// American Express: 34, 37
	if strings.HasPrefix(cardNumber, "34") || strings.HasPrefix(cardNumber, "37") {
		return CardTypeAmex
	}

	// Visa: starts with 4
	if strings.HasPrefix(cardNumber, "4") {
		return CardTypeVisa
	}

	// Mastercard: 51-55, 2221-2720
	if len(cardNumber) >= 2 {
		prefix2 := cardNumber[:2]
		if prefix2 >= "51" && prefix2 <= "55" {
			return CardTypeMastercard
		}
	}
	if len(cardNumber) >= 4 {
		prefix4 := cardNumber[:4]
		if prefix4 >= "2221" && prefix4 <= "2720" {
			return CardTypeMastercard
		}
	}

	// Discover: 6011, 644-649, 65
	if strings.HasPrefix(cardNumber, "6011") || strings.HasPrefix(cardNumber, "65") {
		return CardTypeDiscover
	}
	if len(cardNumber) >= 3 {
		prefix3 := cardNumber[:3]
		if prefix3 >= "644" && prefix3 <= "649" {
			return CardTypeDiscover
		}
	}

	// JCB: 3528-3589
	if len(cardNumber) >= 4 {
		prefix4 := cardNumber[:4]
		if prefix4 >= "3528" && prefix4 <= "3589" {
			return CardTypeJCB
		}
	}

	// Diners Club: 300-305, 36, 38, 39
	if strings.HasPrefix(cardNumber, "36") || strings.HasPrefix(cardNumber, "38") || strings.HasPrefix(cardNumber, "39") {
		return CardTypeDinersClub
	}
	if len(cardNumber) >= 3 {
		prefix3 := cardNumber[:3]
		if prefix3 >= "300" && prefix3 <= "305" {
			return CardTypeDinersClub
		}
	}

	// Maestro: 5018, 5020, 5038, 6304, 6759, 6761-6763
	maestroPrefixes := []string{"5018", "5020", "5038", "6304", "6759", "6761", "6762", "6763"}
	for _, prefix := range maestroPrefixes {
		if strings.HasPrefix(cardNumber, prefix) {
			return CardTypeMaestro
		}
	}

	// UnionPay: 62
	if strings.HasPrefix(cardNumber, "62") {
		return CardTypeChinaUnionPay
	}

	return "0"
}

func GetCardTypeBrandedName(cardType CardType) (string, error) {
	brandedName, ok := CardTypeBrandedNames[cardType]
	if !ok {
		return "", fmt.Errorf("no branded name found for card type %s", cardType)
	}
	return brandedName, nil
}
