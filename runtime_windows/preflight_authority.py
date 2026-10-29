"""Concrete independently pinned preparation and observation bridge.

Operator pins are not cryptographic Human authentication. This module creates
no Human approval or accepted preflight record. Default unbound pins reject
before file/native access. Valid resource use remains separately approved.
"""
import hashlib
from pathlib import Path

from .bootstrap_contract import (FrozenPlan, PreparationPins, canonical, decode, digest, exact,
    fail, relative_name, validate_preparation_pins, validate_preparation_bundle,
    _issue_preparation_permit)
from .launch_contract import ObservationAuthority, SOURCE_FILES, validate_launch_request
from .run_projection import read_projection_file as _read_checked


BASELINE_RUNTIME='4f3606f53cb1007889e077aefe4141da8b4a383e59cc95e2d8d3bc8132d5fd11'
BASELINE_PRODUCT='6e7133a066fbd02e434c8a04029328e74e871f01d6486f162e93d4b3462eec45'


class PinnedPreparationAuthority:
    def __init__(self,pins=None):
        validate_preparation_pins(pins,str(Path(__file__).absolute().parents[1]))
        self.pins=pins
        self.root=Path(pins.product_root)
        self.control=self.root/'runtime_windows'/'.local'/pins.session_id/'preparation_control'
        self._reload()

    @classmethod
    def from_pins(cls,pins=None):
        return cls(pins)

    @property
    def expected_hc_sha256(self):
        return self.pins.expected_hc_original_sha256

    def _reload(self):
        raw_hc=_read_checked(self.control/'hc_original.txt',None,65536)
        raw_bundle=_read_checked(self.control/'preparation_bundle.json',None,2097152)
        if (hashlib.sha256(raw_hc).hexdigest()!=self.pins.expected_hc_original_sha256 or
                hashlib.sha256(raw_bundle).hexdigest()!=self.pins.expected_preparation_bundle_sha256):
            fail('PREPARATION_EXTERNAL_ANCHOR_DRIFT')
        bundle=validate_preparation_bundle(decode(raw_bundle))
        if bundle['session_id']!=self.pins.session_id: fail('PREPARATION_SESSION_MISMATCH')
        docs={};raws={}
        for name,identity in bundle['files'].items():
            raw=_read_checked(self.control.joinpath(*relative_name(name)),identity['size'],2097152)
            if hashlib.sha256(raw).hexdigest()!=identity['sha256']: fail('PREPARATION_PINNED_MEMBER_DRIFT',name)
            raws[name]=raw;docs[name]=decode(raw)
        self._verify_sources(docs)
        self.bundle,self.docs,self.raws=bundle,docs,raws

    def _verify_sources(self,docs):
        from .runtime_admission import verify_current_sources,required_runtime_paths
        from .source_identity import parse_public_lock,verify_public_lock
        runtime_raw=_read_checked(self.root/'runtime_windows'/'RUNTIME_SOURCE_MANIFEST.json',None,1048576)
        if hashlib.sha256(runtime_raw).hexdigest()!=BASELINE_RUNTIME: fail('PREPARATION_PARENT152_IDENTITY')
        registry=verify_current_sources(decode(runtime_raw))
        lock=parse_public_lock(_read_checked(self.root/'runtime_windows'/'public-source-lock.json',None,65536))
        if set(registry)!=required_runtime_paths(lock): fail('PREPARATION_CANDIDATE_CLOSURE')
        verify_public_lock(self.root/'runtime_binding_v1_20261024',lock)
        bootstrap_raw=_read_checked(self.root/'runtime_windows'/'BOOTSTRAP_SOURCE_MANIFEST.json',None,1048576)
        bootstrap=decode(bootstrap_raw)
        exact(bootstrap,('schema','baseline_package_sha256','candidate_runtime_manifest_sha256','member_count','files'),'PREPARATION_SOURCE_MANIFEST_FIELDS')
        if (bootstrap['schema']!='h56.windows-bootstrap-source.v1' or bootstrap['baseline_package_sha256']!=BASELINE_PRODUCT
                or bootstrap['candidate_runtime_manifest_sha256']!=BASELINE_RUNTIME or type(bootstrap['files']) is not list
                or type(bootstrap['member_count']) is not int or bootstrap['member_count']!=len(bootstrap['files'])
                or not 1<=len(bootstrap['files'])<=16):
            fail('PREPARATION_SOURCE_MANIFEST_IDENTITY')
        anchors=set()
        for item in docs.values():
            if type(item) is dict:
                if item.get('schema')=='h56.windows-resource-preparation-plan.v1':
                    from .bootstrap_contract import sha
                    if not sha(item.get('bootstrap_manifest_sha256')): fail('PREPARATION_BOOTSTRAP_ANCHOR_INVALID')
                    anchors.add(item['bootstrap_manifest_sha256'])
                source=(item.get('source_pins') if item.get('schema')=='h56.windows-projection-spec.v1'
                        else item.get('source_identity') if item.get('schema')=='h56.windows-run-projection-plan.v1' else None)
                if type(source) is dict and source.get('bootstrap_source_manifest_sha256'):
                    from .bootstrap_contract import sha
                    if not sha(source['bootstrap_source_manifest_sha256']): fail('PREPARATION_BOOTSTRAP_ANCHOR_INVALID')
                    anchors.add(source['bootstrap_source_manifest_sha256'])
        if anchors!={hashlib.sha256(bootstrap_raw).hexdigest()}: fail('PREPARATION_BOOTSTRAP_SOURCE_NOT_EXTERNALLY_PINNED')
        names=set()
        for item in bootstrap['files']:
            exact(item,('path','size','sha256'),'PREPARATION_SOURCE_MEMBER')
            parts=relative_name(item['path'])
            if item['path'] in names or not item['path'].startswith('runtime_windows/') or '/.local/' in item['path']:
                fail('PREPARATION_SOURCE_MEMBER_SCOPE')
            raw=_read_checked(self.root.joinpath(*parts),item['size'],1048576)
            if hashlib.sha256(raw).hexdigest()!=item['sha256']: fail('PREPARATION_NEW_SOURCE_DRIFT')
            names.add(item['path'])
        needed={'runtime_windows/'+name for name in ('bootstrap_contract.py','run_projection.py','bootstrap_cli.py',
            'resource_prepare.py','preflight_authority.py','probe_backend.py','probe_cli.py','preflight.py')}
        if names!=needed: fail('PREPARATION_SOURCE_CLOSURE_INCOMPLETE')

    def _scope(self,scope):
        if scope not in self.bundle['allowed_operations']: fail('PREPARATION_OPERATION_NOT_APPROVED')

    def _named_plan(self,plan):
        if type(plan) is not FrozenPlan: fail('PREPARATION_FROZEN_PLAN_REQUIRED')
        matches=[name for name,doc in self.docs.items() if digest(doc)==plan.sha256]
        if len(matches)!=1: fail('PREPARATION_PLAN_NOT_UNIQUELY_PINNED')
        return matches[0]

    def read_named(self,name):
        self._reload();relative_name(name)
        if name not in self.raws: fail('PREPARATION_NAMED_INPUT_NOT_PINNED')
        return bytes(self.raws[name])

    def load_plan(self,name,expected_scope):
        raw=self.read_named(name);self._scope(expected_scope)
        return FrozenPlan(decode(raw))

    def authorize(self,plan,scope):
        if scope=='NEGATIVE_PROBE': return self.probe_permit(plan)
        if scope in ('RESOURCE_PREPARE','RESOURCE_READBACK'):
            from .resource_prepare import validate_resource_plan
            value=validate_resource_plan(plan.decoded()).decoded()
            if value['product_root']!=self.pins.product_root or value['session_id']!=self.pins.session_id:
                fail('PREPARATION_RESOURCE_ACTUAL_ROOT_SESSION')
        self._reload();self._scope(scope);self._named_plan(plan)
        return _issue_preparation_permit(plan,scope)

    def resource_permit(self,plan,scope):
        from .resource_prepare import validate_resource_plan
        if scope not in ('RESOURCE_PREPARE','RESOURCE_READBACK'): fail('PREPARATION_RESOURCE_SCOPE_ONLY')
        value=validate_resource_plan(plan.decoded()).decoded()
        if value['product_root']!=self.pins.product_root or value['session_id']!=self.pins.session_id:
            fail('PREPARATION_RESOURCE_ACTUAL_ROOT_SESSION')
        return self.authorize(plan,scope)

    def _resource_inputs(self):
        from .resource_prepare import validate_resource_plan
        for name in ('resource_plan.json','preparation_receipt.json','prelaunch_readback.json','source_scope.json'):
            if name not in self.raws: fail('PREPARATION_OBSERVATION_INPUT_MISSING',name)
        plan=validate_resource_plan(self.docs['resource_plan.json'])
        readback=self.docs['prelaunch_readback.json']
        if (readback.get('schema')!='h56.windows-prelaunch-resource-readback.v1' or readback.get('plan_sha256')!=plan.sha256 or
                readback.get('status')!='NAMED_METADATA_READ_BACK_ONLY' or readback.get('registry_binding')!='BOUND_NAMED_ONLY' or
                readback.get('observation')!='NOT_RUN' or readback.get('negative_probes')!='NOT_RUN' or
                readback.get('core')!='NOT_RUN' or readback.get('isolation_verified') is not False or
                readback.get('authority_granted') is not False):
            fail('PREPARATION_COMPLETE_PRELAUNCH_READBACK_REQUIRED')
        return plan,readback

    def _check_request(self,request):
        resource,readback=self._resource_inputs();value=resource.decoded()
        release=request['release_binding']
        expected=dict(external_decision_sha256=self.expected_hc_sha256,
            source_scope_sha256=hashlib.sha256(self.raws['source_scope.json']).hexdigest(),
            resource_binding_sha256=resource.sha256,
            preflight_receipt_sha256=hashlib.sha256(self.raws['prelaunch_readback.json']).hexdigest())
        if release!=expected: fail('PREPARATION_NONCIRCULAR_RELEASE_BINDING')
        if (request['paths']['product_root']!=self.pins.product_root or value['product_root']!=self.pins.product_root or
                value['session_id']!=self.pins.session_id or request['paths']['runtime_root']!=value['runtime_root'] or
                request['paths']['scratch_root']!=value['paths']['scratch_root'] or
                request['paths']['evidence_root']!=value['paths']['evidence_root'] or
                request['observation_policy']!=readback['observation_policy']):
            fail('PREPARATION_REQUEST_RESOURCE_GEOMETRY')
        profile=request['profile'];observed=readback['profile']
        if any(profile.get(key)!=observed.get(key) for key in ('name','sid','storage_root')):
            fail('PREPARATION_REQUEST_PROFILE_IDENTITY')
        if profile['provisioning_receipt_sha256']!=hashlib.sha256(self.raws['preparation_receipt.json']).hexdigest():
            fail('PREPARATION_PROFILE_PROVISIONING_IDENTITY')
        source=request['source_identity']
        for path,key in (('PACKAGE_MANIFEST.json','product_manifest_sha256'),
                         ('runtime_windows/RUNTIME_SOURCE_MANIFEST.json','runtime_manifest_sha256')):
            raw=_read_checked(self.root.joinpath(*path.split('/')),None,1048576)
            if hashlib.sha256(raw).hexdigest()!=source[key]: fail('PREPARATION_REQUEST_SOURCE_DRIFT')
        for relative in SOURCE_FILES:
            raw=_read_checked(self.root.joinpath(*relative.split('/')),None,65536)
            if hashlib.sha256(raw).hexdigest()!=source['source_files'][relative]: fail('PREPARATION_OBSERVATION_SOURCE_DRIFT')
        python=Path(request['runtime']['python_executable'])
        if hashlib.sha256(_read_checked(python,None,2097152)).hexdigest()!=request['runtime']['python_sha256']:
            fail('PREPARATION_OBSERVATION_PYTHON_DRIFT')
        if 'projection_receipt.json' not in self.docs: fail('PREPARATION_RUNTIME_CLOSURE_MISSING')
        projection=self.docs['projection_receipt.json'];closure=projection.get('dependency_closure')
        from .resource_prepare import validate_projection_ownership
        validate_projection_ownership(resource,self.raws['projection_receipt.json'])
        exact(closure,('schema','files'),'PREPARATION_RUNTIME_CLOSURE_FIELDS')
        if (closure['schema']!='h56.windows-dependency-closure.v1' or type(closure['files']) is not list or
                not 1<=len(closure['files'])<=4096 or digest(closure)!=request['runtime']['closure_sha256']):
            fail('PREPARATION_RUNTIME_CLOSURE_IDENTITY')
        from .launch_contract import contains,windows_path,sha
        names=set();total=0
        for item in closure['files']:
            exact(item,('path','size','sha256'),'PREPARATION_RUNTIME_MEMBER_FIELDS')
            path=windows_path(item['path'])
            if (path in names or not contains(value['runtime_root'],item['path']) or type(item['size']) is not int or
                    not 0<=item['size']<=67108864 or not sha(item['sha256'])): fail('PREPARATION_RUNTIME_MEMBER_SCOPE')
            names.add(path);total+=item['size']
            raw=_read_checked(Path(item['path']),item['size'],67108864)
            if hashlib.sha256(raw).hexdigest()!=item['sha256']: fail('PREPARATION_RUNTIME_MEMBER_DRIFT')
        if total>1073741824 or windows_path(str(python)) not in names: fail('PREPARATION_RUNTIME_EXECUTABLE_CLOSURE')
        if 'check' in request and request['check']=='read_only_source':
            # A safe relative string alone does not make an arbitrary file a
            # registered source target. Consume the fixed candidate/bootstrap
            # inventories that this authority has already verified.
            from .runtime_admission import verify_current_sources
            registered=set(verify_current_sources(decode(_read_checked(self.root/'runtime_windows'/'RUNTIME_SOURCE_MANIFEST.json',None,1048576))))
            bootstrap=decode(_read_checked(self.root/'runtime_windows'/'BOOTSTRAP_SOURCE_MANIFEST.json',None,1048576))
            registered.update(item['path'] for item in bootstrap['files'])
            if any(name not in registered for name in request['target']['relative_files']): fail('PREPARATION_SOURCE_PROBE_UNREGISTERED_TARGET')

    def _fresh_readback(self,request):
        from .resource_prepare import readback_resources
        self._scope('RESOURCE_READBACK')
        resource,expected=self._resource_inputs()
        actual=readback_resources(resource,self.raws['preparation_receipt.json'],
            _issue_preparation_permit(resource,'RESOURCE_READBACK'))
        if actual!=expected: fail('PREPARATION_LIVE_RESOURCES_DRIFT')
        self._check_request(request)

    def observation_authority(self,observation_plan):
        request=observation_plan.decoded()
        plan=FrozenPlan(validate_launch_request(request).decoded())
        self._reload();self._scope('C1_OBSERVE');self._named_plan(plan);self._check_request(request)
        return _PinnedObservationBridge(self,plan)

    def probe_permit(self,probe_plan):
        from .probe_backend import validate_probe_plan
        plan=validate_probe_plan(probe_plan.decoded())
        self._reload();self._scope('NEGATIVE_PROBE');self._named_plan(plan)
        self._check_request(plan.decoded());self._fresh_readback(plan.decoded())
        return _issue_preparation_permit(plan,'NEGATIVE_PROBE')

    def verify_preflight_binding(self,preflight_plan):
        """Only named byte/source/scope checks; no native call or acceptance."""
        from .probe_backend import CHECKS,validate_probe_plan
        self._reload();self._scope('C1_OBSERVE');self._scope('NEGATIVE_PROBE');self._named_plan(preflight_plan)
        value=preflight_plan.decoded()
        exact(value,('schema','session_id','product_root','observer_request','probe_requests',
            'prelaunch_readback_sha256','evidence_root','limits'),'PREPARATION_AGGREGATE_FIELDS')
        if (value['schema']!='h56.windows-neutral-preflight-plan.v1' or value['session_id']!=self.pins.session_id
                or value['product_root']!=self.pins.product_root): fail('PREPARATION_AGGREGATE_ROOT_SESSION')
        observer=validate_launch_request(value['observer_request']);self._named_plan(FrozenPlan(observer.decoded()))
        self._check_request(observer.decoded())
        if (value['evidence_root']!=observer.decoded()['paths']['evidence_root'] or
                value['prelaunch_readback_sha256']!=observer.decoded()['release_binding']['preflight_receipt_sha256']):
            fail('PREPARATION_AGGREGATE_PREREQUISITE')
        exact(value['probe_requests'],CHECKS,'PREPARATION_ALL_FIXED_PROBES_REQUIRED')
        for check,request in value['probe_requests'].items():
            plan=validate_probe_plan(request);self._named_plan(plan);self._check_request(request)
            if (request['check']!=check or request['session_id']!=self.pins.session_id or
                    request['paths']['evidence_root']!=value['evidence_root']): fail('PREPARATION_PROBE_AGGREGATE_BINDING')


class _PinnedObservationBridge(ObservationAuthority):
    def __init__(self,authority,plan):
        self.authority,self.plan=authority,plan

    @property
    def expected_hc_sha256(self):
        return self.authority.expected_hc_sha256

    def authorize(self,plan,release_anchor):
        frozen=FrozenPlan(plan.decoded())
        self.authority._reload();self.authority._scope('C1_OBSERVE');self.authority._named_plan(frozen)
        if frozen.sha256!=self.plan.sha256 or release_anchor!=self.expected_hc_sha256:
            fail('PREPARATION_OBSERVATION_DECISION_DRIFT')
        self.authority._check_request(plan.decoded())

    def verify_preprovisioned_resources(self,plan):
        self.authority._fresh_readback(plan.decoded())
