package main

import "github.com/gin-gonic/gin"

func users(c *gin.Context) {
	name := c.DefaultQuery("name", "")
	db.QueryContext(c, "SELECT * FROM users WHERE name = '"+name+"'")
}