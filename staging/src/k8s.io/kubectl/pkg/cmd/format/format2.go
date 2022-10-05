/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package format

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/delete"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
	"k8s.io/kubectl/pkg/validation"
)

var (
	formatDescLong = templates.LongDesc(i18n.T(`
		TO DO.
	`))

	formatDescExample = templates.Examples(i18n.T(`
		TO DO
	`))
)

type Format2Options struct {
	PrintFlags  *genericclioptions.PrintFlags
	PrintObj    func(obj any) error
	DeleteFlags *delete.DeleteFlags

	Mapper        meta.RESTMapper
	Config        *restclient.Config
	Factory       cmdutil.Factory
	Builder       *resource.Builder
	Validator     validation.Schema
	DeleteOptions *delete.DeleteOptions

	Selector         string
	Namespace        string
	EnforceNamespace bool

	genericclioptions.IOStreams
}

func NewCreateFormatOptions(f cmdutil.Factory, ioStreams genericclioptions.IOStreams) *Format2Options {
	return &Format2Options{
		Factory:     f,
		PrintFlags:  genericclioptions.NewPrintFlags("format").WithTypeSetter(scheme.Scheme),
		DeleteFlags: delete.NewDeleteFlags("The files that contain the configurations to format."),
		IOStreams:   ioStreams,
	}
}

// NewCmdFormat creates the `format` command
func NewCmdFormat2(baseName string, f cmdutil.Factory, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewCreateFormatOptions(f, ioStreams)

	cmd := &cobra.Command{
		Use:                   "format (-f FILENAME)",
		DisableFlagsInUseLine: true,
		Short:                 i18n.T("Format a configuration file"),
		Long:                  formatDescLong,
		Example:               formatDescExample,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete(f, cmd, args))
			cmdutil.CheckErr(o.Run())
		},
	}

	o.PrintFlags.AddFlags(cmd)
	o.DeleteFlags.AddFlags(cmd)

	cmdutil.AddValidateFlags(cmd)

	return cmd
}

func (o *Format2Options) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	var err error

	dynamicClient, err := o.Factory.DynamicClient()
	if err != nil {
		return err
	}

	o.DeleteOptions, err = o.DeleteFlags.ToOptions(dynamicClient, o.IOStreams)
	if err != nil {
		return err
	}

	err = o.DeleteOptions.FilenameOptions.RequireFilenameOrKustomize()
	if err != nil {
		return err
	}

	fieldValidationVerifier := resource.NewQueryParamVerifier(dynamicClient, o.Factory.OpenAPIGetter(), resource.QueryParamFieldValidation)
	validationDirective, err := cmdutil.GetValidationDirective(cmd)
	if err != nil {
		return err
	}
	o.Validator, err = o.Factory.Validator(validationDirective, fieldValidationVerifier)
	if err != nil {
		return err
	}

	o.Namespace, o.EnforceNamespace, err = o.Factory.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	o.Mapper, err = f.ToRESTMapper()
	if err != nil {
		return err
	}

	config, err := f.ToRESTConfig()
	if err != nil {
		return err
	}
	o.Config = config

	o.Builder = o.Factory.NewBuilder()

	return nil
}

func (o *Format2Options) Run() error {
	codec := scheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)
	for _, filename := range o.DeleteOptions.FilenameOptions.Filenames {
		data, err := o.readBytesFromFile(filename)
		if err != nil {
			return err
		}
		unst := unstructured.Unstructured{}
		if err := runtime.DecodeInto(codec, data, &unst); err != nil {
			return err
		}

		unst.GetObjectKind()
		gvk := unst.GetObjectKind().GroupVersionKind()
		if len(gvk.Kind) == 0 {
			return runtime.NewMissingKindErr(string(data))
		}
		name := unst.GetName()
		namespace := unst.GetNamespace()
		resourceVersion := unst.GetResourceVersion()

		fmt.Println(name, namespace, resourceVersion)

		fmt.Println(gvk.GroupKind())
		fmt.Println(gvk.Version)

		mapping, err := o.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			if _, ok := err.(*meta.NoKindMatchError); ok {
				return fmt.Errorf("resource mapping not found for name: %q namespace: %q from %q: %v\nensure CRDs are installed first",
					name, namespace, filename, err)
			}
			return fmt.Errorf("unable to recognize %q: %v", filename, err)
		}
		fmt.Println(mapping)

		gv := gvk.GroupVersion()
		o.Config.GroupVersion = &gv
		restClient, err := restclient.RESTClientFor(o.Config)
		if err != nil {
			return err
		}
		fmt.Println(restClient)

		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()

		// TODO: Consider adding a flag to force to UTF16, apparently some
		// Windows tools don't write the BOM
		utf16bom := unicode.BOMOverride(unicode.UTF8.NewDecoder())
		reader := transform.NewReader(f, utf16bom)
		d := yaml.NewYAMLOrJSONDecoder(reader, 4096)
		ext := runtime.RawExtension{}
		if err := d.Decode(&ext); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("error parsing %s: %v", filename, err)
		}
		// TODO: This needs to be able to handle object in other encodings and schemas.
		ext.Raw = bytes.TrimSpace(ext.Raw)

		decoder := unstructured.UnstructuredJSONScheme
		obj, kind, err := decoder.Decode(ext.Raw, nil, nil)
		if err != nil {
			return fmt.Errorf("unable to decode %q: %v", filename, err)
		}

		helper := resource.NewHelper(restClient, mapping)
		obj2, err := helper.Create(o.Namespace, true, obj)
		if err != nil {
			return cmdutil.AddSourceToErr("formating", filename, err)
		}
		fmt.Println(kind, obj2)

		/*
			fmt.Println(unst, obj, kind)*/
		//restClientGetter.ToRESTConfig,
		fmt.Println(unst)
	}

	r := o.Builder.
		Unstructured().
		Schema(o.Validator).
		ContinueOnError().
		NamespaceParam(o.Namespace).DefaultNamespace().
		FilenameParam(o.EnforceNamespace, &o.DeleteOptions.FilenameOptions).
		LabelSelectorParam(o.Selector).
		Flatten().
		Do()
	objects, err := r.Infos()
	if err != nil {
		return err
	}

	for _, obj := range objects {
		/*accessor, err := metadataAccessor.Accessor(obj)
		if err != nil {
			return err
		}*/

		fmt.Println(obj.Source)
		fmt.Fprintf(o.Out, "\n\n%s", obj)
	}

	/*source := o.DeleteFlags.FileNameFlags.Filenames[0]

	obj, gvk, err := m.decoder.Decode(objects, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decode %q: %v", source, err)
	}

	name, _ := metadataAccessor.Name(obj)
	namespace, _ := metadataAccessor.Namespace(obj)
	resourceVersion, _ := metadataAccessor.ResourceVersion(obj)

	print(name, namespace, resourceVersion)
	ret := &Info{
		Source:          source,
		Namespace:       namespace,
		Name:            name,
		ResourceVersion: resourceVersion,

		Object: obj,
	}*/

	return err
}

func (o *Format2Options) readBytesFromFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return data, nil
}
