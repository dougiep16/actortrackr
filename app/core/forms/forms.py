try:
    from flask import flash
    from flask import g
    from flask_wtf import Form
    from wtforms import StringField
    from wtforms import IntegerField
    from wtforms import SelectField
    from wtforms import DateTimeField
    from wtforms import TextAreaField
    from wtforms import HiddenField
    from wtforms import FieldList
    from wtforms import FormField
    from wtforms import BooleanField
    from wtforms import PasswordField
    from wtforms.validators import DataRequired
    from wtforms.validators import StopValidation
    from wtforms.validators import Required
    from wtforms.validators import Length
    from wtforms.validators import NumberRange
    from wtforms.validators import Optional
    from wtforms.validators import IPAddress
    from wtforms.validators import Email
    from wtforms.validators import EqualTo
    from werkzeug.datastructures import MultiDict
except Exception as e:
    print("Error: {}\nWTForms is not installed, try 'pip install WTForms' and 'pip install Flask-WTF'".format(e))
    exit(1)

import re
from datetime import datetime 
from utils.elasticsearch import *
from app import get_es, get_mysql


'''
WTForms Custom Fields
'''

class NullableIntegerField(IntegerField):
    """
    An IntegerField where the field can be null if the input data is an empty
    string.
    """

    def process_formdata(self, valuelist):
        if valuelist:
            if valuelist[0] == '':
                self.data = None
            else:
                try:
                    self.data = int(valuelist[0])
                except ValueError:
                    self.data = None
                    raise ValueError(self.gettext('Not a valid integer value'))


'''
WTForms Custom Validators
'''

# a validator which makes a field required if another field is set and has a particular value
class RequiredIf(Required):
    
    def __init__(self, other_field, other_value=None, *args, **kwargs):
        self.other_field = other_field
        self.other_value = other_value
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field)
        if other_field is None:
            raise Exception('There is no field named "{}" in form'.format(self.other_field))

        if bool(other_field.data) and (other_field.data == self.other_value):
            super(RequiredIf, self).__call__(form, field)

        elif bool(other_field.data) and not self.other_value:
            super(RequiredIf, self).__call__(form, field)

        else:
            raise StopValidation()

# a validator which makes a field required if another field is set and has a particular value
class RequiredIfNot(Required):
    
    def __init__(self, other_field, other_value, *args, **kwargs):
        self.other_field = other_field
        self.other_value = other_value
        super(RequiredIfNot, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field)
        if other_field is None:
            raise Exception('There is no field named "{}" in form'.format(self.other_field))

        if bool(other_field.data) and (other_field.data != self.other_value):
            super(RequiredIfNot, self).__call__(form, field)

'''
WTForms FieldLists
* These give us the ability to have multiple in the form, jquery 
  handles the addition and substractions
'''

'''
Global Classification Form
'''

class TPXClassificationForm(Form):
    csrf_enabled=False

    a_family = SelectField('class_family', choices = fetch_parent_data('tpx_classification'))
    a_id = SelectField('class_id', choices = fetch_child_data('tpx_classification','Actors'))
    #a_id = SelectField('class_id')

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

    def set_choices(self, choices):
        self.a_id.choices = choices
'''
Actor Sub Forms
'''

class TypeForm(Form):
    csrf_enabled=False

    a_type = SelectField('type', choices = [])

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.a_type.choices = fetch_data('classification')

class MotivationForm(Form):
    csrf_enabled=False

    motivation          = SelectField('motivation', choices = [])
    motivation_other    = StringField('motivation_other', validators=[RequiredIf('motivation','_NEW_'), Length(max=30000)], render_kw={"placeholder": "Enter new motivation"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.motivation.choices = fetch_data('motivation', add_new=True, add_unknown=True)

class AliasForm(Form):
    csrf_enabled=False

    alias = StringField('alias', validators=[Length(max=30000)], render_kw={"placeholder": "Enter an alias for this actor"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

class CommunicationsForm(Form):
    csrf_enabled=False

    a_type = SelectField('type', choices = [])
    a_type_other    = StringField('type_other', validators=[RequiredIf('a_type','_NEW_'), Length(max=30000)], render_kw={"placeholder": "Enter new address type (e.g. AIM)"})
    address = StringField('address', validators=[RequiredIfNot('a_type','Unknown')], render_kw={"placeholder": "Enter a communication address for this actor"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.a_type.choices = fetch_data('communication', add_new=True, add_unknown=True)

class FinancialsForm(Form):
    csrf_enabled=False

    f_type = SelectField('type', choices = [])
    f_type_other    = StringField('type_other', validators=[RequiredIf('f_type','_NEW_'), Length(max=30000)], render_kw={"placeholder": "Enter new financial account type"})
    account = StringField('account', validators=[RequiredIfNot('f_type','Unknown')], render_kw={"placeholder": "Enter the account info for this actor"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.f_type.choices = fetch_data('financial', add_new=True, add_unknown=True)


class LocationsForm(Form):
    csrf_enabled=False

    location = StringField('location', validators=[Length(max=30000)], render_kw={"placeholder": "Enter a frequented location for this actor"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)


class AffiliationsForm(Form):
    csrf_enabled=False

    affiliation          = SelectField('affiliation', choices = [])
    affiliation_other    = StringField('affiliation_other', validators=[RequiredIf('affiliation','_NEW_')], render_kw={"placeholder": "Enter new Country"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.affiliation.choices = fetch_data('country', add_new=True, add_unknown=True)

class KnownTargetsForm(Form):
    csrf_enabled=False

    target          = SelectField('target', choices = [])
    target_other    = StringField('target_other', validators=[RequiredIf('target','_NEW_')], render_kw={"placeholder": "Enter new target"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.target.choices = fetch_data('known_target', add_new=True, add_unknown=True)

class InfrastructureIPv4Form(Form):
    csrf_enabled=False

    ipv4 = StringField('ipv4', validators=[Optional(), IPAddress()], render_kw={"placeholder": "Enter an ipv4 address controlled by this actor"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

class InfrastructureFQDNForm(Form):
    csrf_enabled=False

    fqdn = StringField('fqdn', validators=[Optional()], render_kw={"placeholder": "Enter a domain controlled by this actor"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

class InfrastructureTypesForm(Form):
    csrf_enabled=False

    infra_type = SelectField('type', choices = [])

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.infra_type.choices = fetch_data('infrastructure_type', add_unknown=True)

class DetectionsForm(Form):
    csrf_enabled=False

    d_type = SelectField('type', choices = [])
    rule_id = StringField('id', validators=[RequiredIfNot('d_type','Unknown')], render_kw={"placeholder": "Enter the rule name or ID"})
    rule = TextAreaField('rule', validators=[RequiredIfNot('d_type','Unknown')], render_kw={"placeholder": "Enter the rule body"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        self.d_type.choices = fetch_data('detection_rule', add_unknown=True)

'''
Report Sub Forms 
'''

class ReportSectionsForm(Form):
    csrf_enabled=False

    title   = StringField(validators=[DataRequired()], render_kw={"placeholder": "Enter a title for this section"})
    tlp     = SelectField(validators=[DataRequired()], choices = TLPS)
    text    = TextAreaField(validators=[DataRequired()], render_kw={"placeholder": "Enter the content for this section"})
     
    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

class ReportSourcesForm(Form):
    csrf_enabled=False

    source = StringField(render_kw={"placeholder": "Enter a source for this Report"})

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

'''
Reverse Link Form
'''

class ElementObservablesFrom(Form):
    csrf_enabled=False

    element = BooleanField("")
    element_value = HiddenField()
    element_text = StringField() #used to display data on page

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)
        

'''
Related Form Definitions
'''

class RelatedActorsForm(Form):
    csrf_enabled=False

    data     = SelectField(choices = [("_NONE_","n/a")])
    has_related_elements     = BooleanField("")
    related_elements = FieldList(FormField(ElementObservablesFrom), min_entries=1)

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

        choices = fetch_related_choices('actor')
        self.data.choices = choices

class RelatedTTPsForm(Form):
    csrf_enabled=False

    data     = SelectField(choices = [("_NONE_","n/a")])
    has_related_elements     = BooleanField("")
    related_elements = FieldList(FormField(ElementObservablesFrom), min_entries=1)

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

        choices = fetch_related_choices('ttp')
        self.data.choices = choices

class RelatedReportsForm(Form):
    csrf_enabled=False

    data     = SelectField(choices = [("_NONE_","n/a")])
    has_related_elements     = BooleanField("")
    related_elements = FieldList(FormField(ElementObservablesFrom), min_entries=1)

    #need to disable csrf on sub forms, its already enabled on the parent form, ergo we dont need it!
    def __init__(self, *args, **kwargs):
        super(Form, self).__init__(csrf_enabled=self.csrf_enabled, *args, **kwargs)

        choices = fetch_related_choices('report')
        self.data.choices = choices

'''
Main Form Definitions
'''

#simple search form on home page
class searchForm(Form):
    query = StringField(validators=[DataRequired()], render_kw={"placeholder": "Enter search term(s)"})

class actorForm(Form):
    actor_name              = StringField(validators=[DataRequired(), Length(max=30000)], render_kw={"placeholder": "Enter the name of this actor"})
    actor_description       = TextAreaField(validators=[DataRequired(), Length(max=30000)], render_kw={"placeholder": "Enter the description for this actor"})
    actor_occurred_at       = DateTimeField(format="%m/%d/%Y", default=datetime.now)
    actor_criticality       = IntegerField(validators=[NumberRange(min=1, max=99)], render_kw={"placeholder": "Enter the score for this actor (1 to 99)"})
    actor_class             = FieldList(FormField(TPXClassificationForm), min_entries=1)
    actor_tlp               = SelectField(choices = TLPS)
    actor_type              = FieldList(FormField(TypeForm), min_entries=1)
    actor_motivations       = FieldList(FormField(MotivationForm), min_entries=1)
    actor_aliases           = FieldList(FormField(AliasForm), min_entries=1)
    actor_comms             = FieldList(FormField(CommunicationsForm), min_entries=1)
    actor_financials        = FieldList(FormField(FinancialsForm), min_entries=1)
    actor_locations         = FieldList(FormField(LocationsForm), min_entries=1)
    actor_affliations       = FieldList(FormField(AffiliationsForm), min_entries=1)
    actor_known_targets     = FieldList(FormField(KnownTargetsForm), min_entries=1)
    actor_origin            = FieldList(FormField(AffiliationsForm), min_entries=1)
    actor_infra_ipv4        = FieldList(FormField(InfrastructureIPv4Form), min_entries=1)
    actor_infra_fqdn        = FieldList(FormField(InfrastructureFQDNForm), min_entries=1)
    actor_infra_action      = SelectField(choices = fetch_data('infrastructure_action', add_unknown=True))
    actor_infra_operation   = SelectField(choices = fetch_data('infrastructure_owner', add_unknown=True))
    actor_infra_status      = SelectField(choices = fetch_data('infrastructure_status', add_unknown=True))
    actor_infra_types       = FieldList(FormField(InfrastructureTypesForm), min_entries=1)
    actor_detections        = FieldList(FormField(DetectionsForm), min_entries=1)

    actor_actors            = FieldList(FormField(RelatedActorsForm), min_entries=1)
    actor_reports           = FieldList(FormField(RelatedReportsForm), min_entries=1)
    actor_ttps              = FieldList(FormField(RelatedTTPsForm), min_entries=1)

    #related_elements        = FieldList(FormField(ElementObservablesFrom), min_entries=1)
    related_element_choices = HiddenField('related_element_choices')

    #es fields, when an update occurs, these values should be passed back as well
    doc_index   = HiddenField()
    doc_type    = HiddenField()
    #doc_id      = HiddenField('doc_id')

class reportForm(Form):
    report_name                    = StringField(validators=[DataRequired()], render_kw={"placeholder": "Enter the name for this Report"})
    report_id                      = StringField(validators=[DataRequired()], render_kw={"placeholder": "Enter the identifier for this Report (ex CTIG-20160414-001)"})
    report_description             = TextAreaField(validators=[DataRequired()], render_kw={"placeholder": "Enter the description for this Report"})
    report_occurred_at             = DateTimeField(format="%m/%d/%Y", default=datetime.now)
    report_criticality             = IntegerField(validators=[NumberRange(min=1, max=99)], render_kw={"placeholder": "Enter the score for this Report (1 to 99)"})
    report_class                   = FieldList(FormField(TPXClassificationForm), min_entries=1)
    report_tlp                     = SelectField(choices = TLPS)
    report_source_reliability      = SelectField(choices = SOURCE_RELIABILITY)
    report_info_reliability        = SelectField(choices = INFORMATION_RELIABILITY)
    report_sections                = FieldList(FormField(ReportSectionsForm), min_entries=1)
    report_sources                 = FieldList(FormField(ReportSourcesForm), min_entries=1)

    report_actors                  = FieldList(FormField(RelatedActorsForm), min_entries=1)
    report_ttps                    = FieldList(FormField(RelatedTTPsForm), min_entries=1)
    report_reports                 = FieldList(FormField(RelatedReportsForm), min_entries=1)

    #report_elements               = FieldList(FormField(ElementObservablesFrom), min_entries=1)
    related_element_choices        = HiddenField('related_element_choices')

    #es fields, when an update occurs, these values should be passed back as well
    doc_index   = HiddenField()
    doc_type    = HiddenField()
    #doc_id      = HiddenField()

class ttpForm(Form):
    ttp_name            = StringField(validators=[DataRequired()], render_kw={"placeholder": "Enter the name for this TTP"})
    ttp_description     = TextAreaField(validators=[DataRequired()], render_kw={"placeholder": "Enter the description for this TTP"})
    ttp_first_observed  = DateTimeField(format="%m/%d/%Y", default=datetime.now)
    ttp_criticality     = IntegerField(validators=[NumberRange(min=1, max=99)], render_kw={"placeholder": "Enter the score for this TTP (1 to 99)"})
    ttp_class           = FieldList(FormField(TPXClassificationForm), min_entries=1)
    
    ttp_actors          = FieldList(FormField(RelatedActorsForm), min_entries=1)
    ttp_ttps            = FieldList(FormField(RelatedTTPsForm), min_entries=1)
    ttp_reports         = FieldList(FormField(RelatedReportsForm), min_entries=1)

    #TTPs have no related elements
    #related_elements        = FieldList(FormField(ElementObservablesFrom), min_entries=1)
    #related_element_choices = HiddenField('related_element_choices')

    #es fields, when an update occurs, these values should be passed back as well
    doc_index   = HiddenField()
    doc_type    = HiddenField()
    #doc_id      = HiddenField()

'''
Admin Form Definitions
'''

class sendUserEmailForm(Form):
    message_email       = StringField(validators=[DataRequired(),Email()], render_kw={"placeholder": "Enter the user's email"})
    message_subject     = StringField(validators=[DataRequired()], render_kw={"placeholder": "Enter the email subject"})
    message_body        = TextAreaField(validators=[DataRequired()], render_kw={"placeholder": "Enter the email body"})

'''
User Form Definitions
'''

class loginForm(Form):
    user_email      = StringField(validators=[DataRequired(),Email()], render_kw={"placeholder": "Enter your email"})
    user_password   = PasswordField(validators=[DataRequired()], render_kw={"placeholder": "Enter your password"})
    

class userEmailForm(Form):
    user_email      = StringField(validators=[DataRequired(),Email()], render_kw={"placeholder": "Enter your email"})

class passwordPerformResetForm(Form):
    user_password   = PasswordField(validators=[DataRequired(), Length(min=7, max=256)], render_kw={"placeholder": "Enter your new password"})
    user_password2  = PasswordField(validators=[EqualTo('user_password', message="Field must match Password")], render_kw={"placeholder": "Enter your new password again"})

    def validate(self):
        #flash("Password is still a string field, change this", "warning")

        try:
            rv = Form.validate(self)
            if not rv:
                return False

            #check password complexity
            pwd = self.user_password.data

            # searching for digits
            digit_error = re.search(r"\d", pwd) is None

            # searching for uppercase
            uppercase_error = re.search(r"[A-Z]", pwd) is None

            # searching for lowercase
            lowercase_error = re.search(r"[a-z]", pwd) is None

            # searching for symbols
            #NOTE: if viewing in sublime, this is correct below, the format is jacked
            symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', pwd) is None

            if digit_error or uppercase_error or lowercase_error or symbol_error:
                self.user_password.errors.append('Password must contain at least one number, one lowercase letter, one uppercase letter and one symbol')
                return False
        except Exception as e:
            flash("Error validating form, details: {}".format(e))
            return False

        return True

class registerForm(Form):
    user_name       = StringField(validators=[DataRequired(), Length(max=256)], render_kw={"placeholder": "Enter your name"})
    user_email      = StringField(validators=[DataRequired(),Email(), Length(max=256)], render_kw={"placeholder": "Enter your email"})
    user_password   = PasswordField(validators=[DataRequired(), Length(min=7, max=256)], render_kw={"placeholder": "Enter your password"})
    user_password2  = PasswordField(validators=[EqualTo('user_password', message="Field must match Password")], render_kw={"placeholder": "Enter your password again"})
    user_company    = StringField(validators=[DataRequired(), Length(max=256)], render_kw={"placeholder": "Enter your company"})
    user_reason     = StringField(validators=[DataRequired(), Length(max=1024)], render_kw={"placeholder": "Enter your reason for using ActorTrackr"})


    def validate(self):
        #flash("Password is still a string field, change this", "warning")

        try:
            rv = Form.validate(self)
            if not rv:
                return False


            #check to see if user already exists
            #theres probably still a race condition here, not sure how to prevent it
            try:
                conn=get_mysql().cursor()
                conn.execute("SELECT id FROM users WHERE email = %s", (self.user_email.data.strip(),))
                user_exists = (len(conn.fetchall()) != 0)
                conn.close()
                if user_exists:
                    self.user_email.errors.append('Email address is already registered')
                    return False
            except Exception as s:
                conn.close()
                raise s

            

            #check password complexity
            pwd = self.user_password.data

            # searching for digits
            digit_error = re.search(r"\d", pwd) is None

            # searching for uppercase
            uppercase_error = re.search(r"[A-Z]", pwd) is None

            # searching for lowercase
            lowercase_error = re.search(r"[a-z]", pwd) is None

            # searching for symbols
            #NOTE: if viewing in sublime, this is correct below, the format is jacked
            symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', pwd) is None 

            if digit_error or uppercase_error or lowercase_error or symbol_error:
                self.user_password.errors.append('Password must contain at least one number, one lowercase letter, one uppercase letter and one symbol')
                return False
        except Exception as e:
            flash("Error validating form, details: {}".format(e))
            return False

        return True





