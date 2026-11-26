package controller

// Admins CRUD over the VPN permission model, ported from vpn-ui
// web/controller/admin.go onto internal/vpn/adminaccess. Every route is
// super-admin only; the gating lives on the group, not in the handlers.

import (
	"strconv"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/adminaccess"
	"github.com/ImSoheilPx/pxpanel/internal/web/session"

	"github.com/gin-gonic/gin"
)

// adminForm is the add/edit payload. Bodies arrive form-urlencoded (the panel's
// axios layer Qs.stringify's everything), so these bind by `form` tag via
// ShouldBind, never ShouldBindJSON. Permissions arrive as repeated `permissions`
// keys, which is what Qs's arrayFormat:'repeat' emits for an array.
type adminForm struct {
	Id           int      `json:"id" form:"id"`
	Username     string   `json:"username" form:"username"`
	Password     string   `json:"password" form:"password"`
	Nickname     string   `json:"nickname" form:"nickname"`
	Enable       bool     `json:"enable" form:"enable"`
	IsSuperAdmin bool     `json:"isSuperAdmin" form:"isSuperAdmin"`
	Permissions  []string `json:"permissions" form:"permissions"`
	// InboundIds arrives as repeated `inboundIds` keys (Qs arrayFormat:'repeat').
	// A blank entry is how the UI sends "none": an omitted field would bind as nil
	// and could not be told apart from "leave alone".
	InboundIds []string `json:"inboundIds" form:"inboundIds"`
}

// inboundIds parses the wire form's ids, dropping blanks and unparseable entries
// rather than failing the whole save over one bad value.
func (f *adminForm) inboundIds() []int {
	out := make([]int, 0, len(f.InboundIds))
	for _, raw := range f.InboundIds {
		if raw == "" {
			continue
		}
		if id, err := strconv.Atoi(raw); err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

// spec maps the wire form onto the service's shape.
func (f *adminForm) spec() adminaccess.AdminSpec {
	return adminaccess.AdminSpec{
		Username:     f.Username,
		Password:     f.Password,
		Nickname:     f.Nickname,
		Permissions:  model.PermissionsFromSlugs(f.Permissions),
		Enable:       f.Enable,
		IsSuperAdmin: f.IsSuperAdmin,
		InboundIds:   f.inboundIds(),
	}
}

// VpnAdminsController serves the Admins CRUD.
type VpnAdminsController struct {
	BaseController
}

// NewVpnAdminsController creates the controller and initializes its routes.
func NewVpnAdminsController(g *gin.RouterGroup) *VpnAdminsController {
	a := &VpnAdminsController{}
	a.initRouter(g)
	return a
}

func (a *VpnAdminsController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/admins")
	g.Use(requireSuperAdminVpn())

	g.GET("/list", a.list)
	g.GET("/permissions", a.permissions)
	g.GET("/inbounds", a.inbounds)
	g.POST("/add", a.add)
	g.POST("/update/:id", a.update)
	g.POST("/del/:id", a.del)
	g.POST("/reassign/:from/:to", a.reassign)
}

func (a *VpnAdminsController) list(c *gin.Context) {
	admins, err := adminaccess.GetAdmins()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.title"), err)
		return
	}
	jsonObj(c, admins, nil)
}

// permissions returns the canonical slug list so the UI renders exactly the
// permissions this build enforces, rather than a hard-coded copy that can drift.
func (a *VpnAdminsController) permissions(c *gin.Context) {
	jsonObj(c, model.AllPermissions, nil)
}

// inbounds lists every inbound as {id, remark, protocol, port}, for the modal's
// access checklist. Super-admin only (the whole group is), so a panel-wide list is
// the point rather than a leak.
func (a *VpnAdminsController) inbounds(c *gin.Context) {
	list, err := adminaccess.AllInboundsBrief()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.title"), err)
		return
	}
	jsonObj(c, list, nil)
}

func (a *VpnAdminsController) add(c *gin.Context) {
	form := &adminForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.add"), err)
		return
	}
	_, err := adminaccess.AddAdmin(form.spec())
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.add"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.admins.add"), nil)
}

func (a *VpnAdminsController) update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.edit"), err)
		return
	}
	form := &adminForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.edit"), err)
		return
	}
	// Guard the caller against locking themselves out: the service refuses to strand
	// the panel with no super admin, but it cannot tell that this edit is
	// self-inflicted.
	if me := session.GetLoginUser(c); me != nil && me.Id == id && (!form.IsSuperAdmin || !form.Enable) {
		jsonMsg(c, I18nWeb(c, "pages.admins.edit"), errSelfDemote)
		return
	}
	err = adminaccess.UpdateAdmin(id, form.spec())
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.edit"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.admins.edit"), nil)
}

func (a *VpnAdminsController) del(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.del"), err)
		return
	}
	if me := session.GetLoginUser(c); me != nil && me.Id == id {
		jsonMsg(c, I18nWeb(c, "pages.admins.del"), errSelfDelete)
		return
	}
	if err := adminaccess.DeleteAdmin(id); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.del"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.admins.del"), nil)
}

func (a *VpnAdminsController) reassign(c *gin.Context) {
	from, err := strconv.Atoi(c.Param("from"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.reassign"), err)
		return
	}
	to, err := strconv.Atoi(c.Param("to"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.reassign"), err)
		return
	}
	moved, err := adminaccess.ReassignInbounds(from, to)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.admins.reassign"), err)
		return
	}
	jsonObj(c, gin.H{"moved": moved}, nil)
}
