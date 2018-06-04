# -*- coding: utf-8 -*-
from . import api
from lib.ReturnMessage import returnMsg, returnErrorMsg, returnNoneMsg
from flask_jwt_extended import create_access_token, create_refresh_token, get_jti
from flask import request, json, jsonify, url_for
import cec
from  model.User import User
from werkzeug.security import generate_password_hash, check_password_hash
from config import db
from .Auth_jwt import Authors
from lib import common
import time

# 注册
@api.route('/register', methods=['POST'])
def register():
    if not request.json:
        resultDict = returnNoneMsg("failed!")
        return jsonify(resultDict)
    jsonData = request.get_data()
    dataDict = json.loads(jsonData)
    name = dataDict.get('name', None)
    password = dataDict.get('password', None)
    email = dataDict.get('email', None)
    phone = dataDict.get('phone', None)

    user_info = User.query.filter_by(user_name=name).first()
    if user_info:
        resultDict = returnNoneMsg(cec.code_1)
        return jsonify(resultDict)

    user = User(
        user_name=name,
        email=email,
        phone=phone,
        user_password=generate_password_hash(password),
        user_reg_ip=request.remote_addr
    )
    db.session.add(user)
    db.session.commit()

    resultDict = returnMsg("register success")
    return jsonify(resultDict)


# 登录
@api.route('/login', methods=['POST'])
def login():
    if not request.json:
        resultDict = returnNoneMsg("failed!")
        return jsonify(resultDict)
    jsonData = request.get_data()
    dataDict = json.loads(jsonData)
    name = dataDict.get("name", None)
    password = dataDict.get("password", None)
    if name and password:

        user = User.query.filter_by(user_name=name).first()
        if not user :
            resultDict = returnNoneMsg("user not exists")
            return jsonify(resultDict)
        if not user.check_pwd(password):
            resultDict = returnNoneMsg("Password error")
            return jsonify(resultDict)
    else:
        resultDict = returnNoneMsg("Bad counselorName or counselorPwd")
        return jsonify(resultDict)

    if user:

        Author = Authors()
        res = Author.authenticate(name, password)
        return res
    else:
        resultDict = returnNoneMsg("this user not exit")
    return jsonify(resultDict)


@api.route('/getUser', methods=['GET'])
def get():
    """
    获取用户信息
    :return: json
    """

    Author = Authors()
    result = Author.identify(request)
    if (result['status'] and result['data']):

        user = User.query.filter_by(id=result['data']).first()
        timeStamp = user.login_time
        timeArray = time.localtime(timeStamp)
        otherStyleTime = time.strftime("%Y--%m--%d %H:%M:%S", timeArray)
        returnUser = {
            'id': user.id,
            'username': user.user_name,
            'email': user.email,
            'phone': user.phone,
            'login_time':otherStyleTime,
        }
        result = common.trueReturn(returnUser, "请求成功")
    return jsonify(result)
