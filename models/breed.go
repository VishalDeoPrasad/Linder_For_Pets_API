package models

import "gorm.io/gorm"

type Breed struct {
	gorm.Model
	Name            string
	Size            string
	Color           string
	Weight          string
	EnergyLevel     string
	AggressionLevel string
}

type NewBreedReq struct {
	Name            string `json:"name" validate:"required"`
	Size            string `json:"size" validate:"required"`
	Color           string `json:"color" validate:"required"`
	Weight          string `json:"weight" validate:"required"`
	EnergyLevel     string `json:"energyLevel" validate:"required"`
	AggressionLevel string `json:"aggressionLevel" validate:"required"`
}
