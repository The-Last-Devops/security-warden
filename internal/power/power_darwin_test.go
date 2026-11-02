package power

import "testing"

func TestParsePmset(t *testing.T) {
	if !parsePmset("Now drawing from 'Battery Power'\n -InternalBattery-0 80%; discharging") {
		t.Error("battery")
	}
	if parsePmset("Now drawing from 'AC Power'\n -InternalBattery-0 100%; charged") {
		t.Error("AC")
	}
}
