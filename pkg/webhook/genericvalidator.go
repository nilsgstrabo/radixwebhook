package webhook

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var _ webhook.CustomValidator = &AdmissionValidator[runtime.Object]{}

type ValidationFunc[TObj runtime.Object] func(obj TObj) ([]string, error)

type AdmissionValidator[TObj runtime.Object] struct {
	Logger           logr.Logger
	CreateValidation ValidationFunc[TObj]
	UpdateValidation ValidationFunc[TObj]
	DeleteValidation ValidationFunc[TObj]
}

func (v *AdmissionValidator[TObj]) ValidateCreate(ctx context.Context, obj runtime.Object) (warnings admission.Warnings, err error) {
	request, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, err
	}

	v.Logger.Info(fmt.Sprintf("create %s: %s/%s", obj.GetObjectKind().GroupVersionKind().String(), request.Namespace, request.Name))

	return v.runValidation(obj, v.CreateValidation)
}

func (v *AdmissionValidator[TObj]) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (warnings admission.Warnings, err error) {
	request, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, err
	}

	v.Logger.Info(fmt.Sprintf("update %s: %s/%s", newObj.GetObjectKind().GroupVersionKind().String(), request.Namespace, request.Name))

	return v.runValidation(newObj, v.UpdateValidation)
}

func (v *AdmissionValidator[TObj]) ValidateDelete(ctx context.Context, obj runtime.Object) (warnings admission.Warnings, err error) {
	request, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, err
	}

	v.Logger.Info(fmt.Sprintf("delete %s: %s/%s", obj.GetObjectKind().GroupVersionKind().String(), request.Namespace, request.Name))

	return v.runValidation(obj, v.DeleteValidation)
}

func (v *AdmissionValidator[TObj]) runValidation(obj runtime.Object, validate ValidationFunc[TObj]) (admission.Warnings, error) {
	tobj, ok := obj.(TObj)
	if !ok {
		v.Logger.Info("incorrect object type")
		return nil, nil
	}

	if validate == nil {
		return nil, nil
	}

	warnings, err := validate(tobj)
	if len(warnings) > 0 {
		v.Logger.Info(fmt.Sprintf("admission warnings: %s", strings.Join(warnings, ";")))
	}
	if err != nil {
		v.Logger.Info(fmt.Sprintf("admission error: %s", err.Error()))
	}

	return warnings, err
}
