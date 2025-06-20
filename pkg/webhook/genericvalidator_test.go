package webhook_test

import (
	"context"
	"os"
	"testing"

	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/radixvalidators"
	"github.com/go-logr/logr"
	"github.com/nilsgstrabo/radixwebhook/pkg/webhook"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"sigs.k8s.io/yaml"
)

func Test_X(t *testing.T) {

	adm := webhook.AdmissionValidator[*v1.RadixApplication]{
		Logger: logr.Logger{},
		CreateValidation: func(obj *v1.RadixApplication) ([]string, error) {
			return nil, radixvalidators.IsRadixApplicationValid(obj)
		},
	}

	raData, err := os.ReadFile("/home/nilsstrabo/src/github.com/nilsgstrabo/radixwebhook/testdata/ra1.yaml")
	require.NoError(t, err)
	var ra v1.RadixApplication
	err = yaml.Unmarshal(raData, &ra)
	require.NoError(t, err)
	ctx := admission.NewContextWithRequest(context.Background(), admission.Request{})
	adm.ValidateCreate(ctx, &ra)

}
