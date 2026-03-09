"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts"
import { Banknote, FileText, TrendingUp, Building2, Download, FileSpreadsheet, XCircle, AlertTriangle, CheckCircle2, Filter } from "lucide-react"
import type { Bank, Check, User } from "@/lib/db"
import { exportToExcel, exportStatsToPDF } from "@/lib/export-utils"
import { CheckHistory } from "./check-history"
import { Label } from "@/components/ui/label"
import { parseFlexibleDate } from "@/lib/date-utils"

interface DashboardStatsProps {
  stats: {
    totalAmount: number
    totalChecks: number
    checksByBank: Record<string, number>
    amountByUser: Record<string, number>
  }
  checks: Check[]
  users: User[]
  currentUser: User
  regions: Array<{ id: number; name: string; wilayas: string[] }>
  banks: Bank[]
}

const COLORS = ["#3b82f6", "#8b5cf6", "#06b6d4", "#10b981", "#f59e0b", "#ef4444"]

const formatNumber = (num: number) => {
  return num.toFixed(2).replace('.', ',').replace(/(\d)(?=(\d{3})+(?!\d))/g, '$1\u00A0')
}

export function DashboardStats({ stats, checks, users, currentUser, regions = [], banks }: DashboardStatsProps) {
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [showFilters, setShowFilters] = useState(false)

  // Le backend filtre déjà les chèques par région pour les profils régionaux.
  // Le frontend affine en vérifiant que l'émetteur est bien un profil régional de la même région.
  let filteredChecks = currentUser.role === "regionale" && currentUser.region
    ? checks.filter(check => {
        const checkUser = users.find(u => String(u.id) === String(check.userId))
        // Si l'utilisateur n'est pas trouvé dans la liste, on fait confiance au backend
        if (!checkUser) return true
        return checkUser.role === "regionale" && checkUser.region === currentUser.region
      })
    : checks

  // Appliquer le filtre de date
  if (startDate || endDate) {
    filteredChecks = filteredChecks.filter(check => {
      const checkDate = parseFlexibleDate(check.date)
      if (!checkDate) return false

      const start = startDate === "" ? null : parseFlexibleDate(startDate)
      const end = endDate === "" ? null : parseFlexibleDate(endDate)
      const matchesStartDate = !start || checkDate >= start
      const matchesEndDate = !end || checkDate <= end
      return matchesStartDate && matchesEndDate
    })
  }

  // Séparer les chèques par statut (traiter les chèques sans status comme "emit")
  const activeChecks = filteredChecks.filter(c => !c.status || c.status === "emit")
  const canceledChecks = filteredChecks.filter(c => c.status === "annule")
  const rejectedChecks = filteredChecks.filter(c => c.status === "rejete")

  // Recalculer les statistiques avec UNIQUEMENT les chèques émis (status="emit")
  const filteredStats = {
    totalAmount: activeChecks.reduce((sum, c) => sum + c.amount, 0),
    totalChecks: activeChecks.length,
    emittedChecks: activeChecks.length,
    canceledChecks: canceledChecks.length,
    rejectedChecks: rejectedChecks.length,
    checksByBank: activeChecks.reduce((acc, c) => {
      acc[c.bank] = (acc[c.bank] || 0) + 1
      return acc
    }, {} as Record<string, number>),
    amountByUser: activeChecks.reduce((acc, c) => {
      acc[String(c.userId)] = (acc[String(c.userId)] || 0) + c.amount
      return acc
    }, {} as Record<string, number>)
  }

  const userMap = users.reduce(
    (acc, user) => {
      acc[String(user.id)] = user.email
      return acc
    },
    {} as Record<string, string>,
  )

  const bankData = Object.entries(filteredStats.checksByBank || {}).map(([bank, count]) => ({
    bank,
    count,
  }))

  const userAmountData = Object.entries(filteredStats.amountByUser || {}).map(([userId, amount]) => ({
    email: userMap[userId] || "Inconnu",
    amount,
  }))

  const pieData = Object.entries(filteredStats.checksByBank || {}).map(([name, value]) => ({
    name,
    value,
  }))

  const handleExportExcel = async () => {
    exportToExcel(filteredStats, filteredChecks, users)
    
    // Log export to audit
    try {
      await fetch("/api/checks/log-export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          format: "Excel (Stats)",
          recordCount: filteredChecks.length,
          dateRange: null,
        }),
      })
    } catch (error) {
      console.error("Failed to log export:", error)
    }
  }

  const handleExportPDF = async () => {
    exportStatsToPDF(filteredStats, filteredChecks, users)
    
    // Log export to audit
    try {
      await fetch("/api/checks/log-export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          format: "PDF (Stats)",
          recordCount: filteredChecks.length,
          dateRange: null,
        }),
      })
    } catch (error) {
      console.error("Failed to log export:", error)
    }
  }

  return (
    <div className="space-y-6">
      {/* Bouton pour afficher/masquer les filtres */}
      <div className="flex justify-end">
        <Button onClick={() => setShowFilters(!showFilters)} variant="outline" size="sm" className="gap-2">
          <Filter className="h-4 w-4" style={{ color: '#e82c2a' }} />
          {showFilters ? "Masquer les filtres" : "Afficher les filtres"}
        </Button>
      </div>

      {/* Filtres de date */}
      {showFilters && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Filtres par date</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="startDate">Date de début</Label>
                <Input
                  id="startDate"
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="endDate">Date de fin</Label>
                <Input
                  id="endDate"
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                />
              </div>
            </div>
            {(startDate || endDate) && (
              <Button
                variant="outline"
                size="sm"
                className="mt-4"
                onClick={() => {
                  setStartDate("")
                  setEndDate("")
                }}
              >
                Réinitialiser les filtres
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Montant Total</CardTitle>
            <Banknote className="h-4 w-4" style={{ color: '#e82c2a' }} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatNumber(filteredStats.totalAmount || 0)} DZD</div>
            <p className="text-xs text-muted-foreground">Chèques émis uniquement</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Chèques Émis</CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{(filteredStats.emittedChecks || 0).toLocaleString('fr-FR')}</div>
            <p className="text-xs text-muted-foreground">En circulation</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Chèques Annulés</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{(filteredStats.canceledChecks || 0).toLocaleString('fr-FR')}</div>
            <p className="text-xs text-muted-foreground">Annulés</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Chèques Rejetés</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">{(filteredStats.rejectedChecks || 0).toLocaleString('fr-FR')}</div>
            <p className="text-xs text-muted-foreground">Rejetés</p>
          </CardContent>
        </Card>
      </div>

      <CheckHistory checks={filteredChecks} users={users} banks={banks} />
    </div>
  )
}
