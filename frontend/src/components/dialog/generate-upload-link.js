import React from 'react';
import { gettext } from '../../utils/constants';
import PropTypes from 'prop-types';
import { seafileAPI } from '../../utils/seafile-api';
import { Button, Form, FormGroup, Label, Input, InputGroup, InputGroupAddon } from 'reactstrap';

const propTypes = {
  itemPath: PropTypes.string.isRequired,
  repoID: PropTypes.string.isRequired
};

class GenerateUploadLink extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      showPasswordInput: false,
      passwordVisible: false,
      password: '',
      passwdnew: '',
      link: '',
      token:''
    }
  }

  componentDidMount() {
    this.getUploadLink();
  }

  getUploadLink = () => {
    let path = this.props.itemPath;
    let repoID = this.props.repoID; 
    seafileAPI.getUploadLinkt(repoID, path).then((res) => {
      if (res.data.length !== 0) {
        this.setState({
          link: res.data[0].link,
          token: res.data[0].token,
        });
      }
    })
  }


  addPassword = () => {
    this.setState({
      showPasswordInput: !this.state.showPasswordInput
    })
  }

  togglePasswordVisible = () => {
    this.setState({
      passwordVisible: !this.state.passwordVisible
    })
  }

  generatePassword = () => {
    let val = Math.random().toString(36).substr(2);
    this.setState({
      password: val,
      passwordnew: val
    });
  }

  inputPassword = (e) => {
    this.setState({
      password: e.target.value
    });
  }

  inputPasswordNew = (e) => {
     this.setState({
      passwordnew: e.target.value
    });
  }

  generateUploadLink = () => {
    let path = this.props.itemPath;
    let repoID = this.props.repoID; 

    if (this.state.showPasswordInput && (this.state.password == '')) {
      this.setState({
        errorInfo: gettext('Please enter password')
      });
    }
    else if (this.state.showPasswordInput && this.state.password.length < 8) {
      this.setState({
        errorInfo: gettext('Password is too short')
      });
    }
    else if (this.state.password !== this.state.passwordnew) {
      this.setState({
        errorInfo: gettext("Passwords don't match")
      });
    } else {
      seafileAPI.createUploadLink(repoID, path, this.state.password)
        .then((res) => {
          this.setState({
            link: res.data.link,
            token: res.data.token  
          })    
        })
    }
  }

  deleteUploadLink = () => {
    seafileAPI.deleteUploadLink(this.state.token)
      .then((res) => {
        this.setState({
          link: '',
          token: '',
          showPasswordInput: false,
          password: '',
          passwordnew: '',
        })
      })
  }

  render() {
    if (this.state.link) {
      return (
        <Form>
          <p>{this.state.link}</p>
          <Button onClick={this.deleteUploadLink}>{gettext('Delete')}</Button>
        </Form>
      );
    } else {
      return (
        <Form>
          <FormGroup>
            <Label>{gettext('You can share the generated link to others and then they can upload files to this directory via the link.')}</Label>
          </FormGroup>
          <FormGroup check>
            <Label check>
              <Input type="checkbox" onChange={this.addPassword}/> {'  '}{gettext('Add password protection')} 
            </Label>
          </FormGroup>
          { this.state.showPasswordInput &&
            <FormGroup>
              <Label>{gettext('Password')}({gettext('at least 8 characters')})</Label>
              <InputGroup>
              <Input type={this.state.passwordVisible ? 'text':'password'} value={this.state.password} onChange={this.inputPassword}/>
              <InputGroupAddon addonType="append">
                <Button onClick={this.togglePasswordVisible}><i className={`fas ${this.state.passwordVisible ? 'fa-eye': 'fa-eye-slash'}`}></i></Button>
                <Button onClick={this.generatePassword}><i className="fas fa-magic"></i></Button>
              </InputGroupAddon>
              </InputGroup>
              <Label>{gettext('Password again')}</Label>
              <Input type={this.state.passwordVisible?'text':'password'} value={this.state.passwordnew} onChange={this.inputPasswordNew} />
            </FormGroup>
          }
          <Label>{this.state.errorInfo}</Label><br/>
          <Button onClick={this.generateUploadLink}>{gettext('Generate')}</Button>
        </Form>
      );
    }
  }
}

GenerateUploadLink.propTypes = propTypes;

export default GenerateUploadLink;
