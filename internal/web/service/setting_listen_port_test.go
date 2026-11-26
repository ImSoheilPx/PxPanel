package service

import "testing"

func TestGetListenPort(t *testing.T) {
	cases := []struct {
		name        string
		pxpanelPort string
		want        int
	}{
		// 2053 is the default webPort on a fresh database.
		{"PXPANEL_PORT unset", "", 2053},
		{"valid PXPANEL_PORT", "8443", 8443},
		{"PXPANEL_PORT not a number", "abc", 2053},
		{"PXPANEL_PORT out of range", "70000", 2053},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupConflictDB(t)
			t.Setenv("PXPANEL_PORT", tc.pxpanelPort)
			got, err := (&SettingService{}).GetListenPort()
			if err != nil {
				t.Fatalf("GetListenPort: %v", err)
			}
			if got != tc.want {
				t.Fatalf("GetListenPort() = %d, want %d", got, tc.want)
			}
		})
	}
}
