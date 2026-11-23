import React from 'react'
import { Bar, BarChart, CartesianGrid, Cell, LabelList, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Empty, Panel } from './ui.jsx'

const axis = { axisLine: false, tickLine: false, tick: { fill: '#6b5661', fontSize: 11 } }

function ChartTooltip({ active, payload, unit }) {
  const point = payload?.[0]?.payload
  if (!active || !point) return null
  return <div className="chart-tooltip"><strong>{point.detail ?? point.name}</strong>
    <span>{point.rated === false ? 'Unrated' : point.value + unit}</span></div>
}

export function ChartKey({ points, showValues = true }) {
  return <ul className="chart-key">{points.map(point => <li key={point.id ?? point.name}>
    <span className="chart-swatch" style={{ '--chart-color': point.fill }} aria-hidden="true" />
    <span>{point.name}</span>{showValues && <> <strong>{point.value}</strong></>}
  </li>)}</ul>
}

function ChartBar({ x, y, width, height, payload, horizontal, onSelect, getLabel }) {
  const length = horizontal ? width : height
  const hitWidth = horizontal ? Math.max(width, 24) : width
  const hitHeight = horizontal ? height : Math.max(height, 18)
  const hitTop = horizontal ? y : y + height - hitHeight
  const activate = () => onSelect(payload)
  return <g role="button" tabIndex={0} className="chart-trigger" aria-label={getLabel(payload)} onClick={activate} onKeyDown={event => {
    if (event.key !== 'Enter' && event.key !== ' ') return
    event.preventDefault()
    activate()
  }}>
    <rect className="chart-hit" x={x} y={hitTop} width={hitWidth} height={hitHeight} rx={4} />
    {length > 0 ? <rect x={x} y={y} width={width} height={height} rx={4} fill={payload.fill} /> :
      <rect x={x} y={horizontal ? y : y - 2} width={horizontal ? 2 : width} height={horizontal ? height : 2} fill={payload.fill} />}
  </g>
}

export function Bars({ title, points, description, unit = '', horizontal = false, onSelect, getLabel, children }) {
  const margin = horizontal ? { top: 5, right: 26, left: 2, bottom: 0 } : { top: 17, right: 6, left: 0, bottom: 0 }
  const shape = onSelect ? props => <ChartBar {...props} horizontal={horizontal} onSelect={onSelect} getLabel={getLabel} /> : undefined
  const xAxis = horizontal ? { type: 'number', domain: [0, 100], ticks: [0, 25, 50, 75, 100] } :
    { type: 'category', dataKey: point => point.axisLabel ?? point.name, interval: 0 }
  const yAxis = horizontal ? { type: 'category', dataKey: 'name', width: 60 } : { type: 'number', width: 28, allowDecimals: false }
  return <Panel title={title} description={description} className="dashboard-chart">
    {points.length ? <>
      <div className="chart-plot" aria-hidden={onSelect ? undefined : true}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={points} layout={horizontal ? 'vertical' : 'horizontal'} margin={margin}>
            <CartesianGrid stroke="#eadddc" horizontal={!horizontal} vertical={horizontal} strokeDasharray="3 4" />
            <XAxis {...xAxis} {...axis} />
            <YAxis {...yAxis} {...axis} />
            <Tooltip content={<ChartTooltip unit={unit} />} cursor={{ fill: '#f2e4e889' }} />
            <Bar dataKey="value" shape={shape} radius={[4, 4, 0, 0]} maxBarSize={horizontal ? 16 : 35} isAnimationActive={false}>
              {points.map(point => <Cell key={point.id ?? point.name} fill={point.fill} />)}
              <LabelList valueAccessor={entry => entry.payload.rated === false ? '—' : entry.value}
                position={horizontal ? 'right' : 'top'} fill="#634454" fontSize={10}
                formatter={value => horizontal || Number(value) > 0 ? value : ''} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      {children ?? (!onSelect && <ChartKey points={points} />)}
    </> : <Empty>No data in this scope.</Empty>}
  </Panel>
}

export function Distribution({ title, points, description, unit = '', doughnut = false, totalLabel, empty }) {
  const total = points.reduce((sum, point) => sum + point.value, 0)
  return <Panel title={title} description={description} className="dashboard-chart">
    {total > 0 ? <div className="chart-plot chart-distribution" aria-hidden="true">
      {doughnut && <div className="chart-center"><strong>{total}</strong><span>{totalLabel}</span></div>}
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={points} dataKey="value" nameKey="name" outerRadius="87%" innerRadius={doughnut ? '62%' : 0}
            paddingAngle={2} stroke="none" isAnimationActive={false}>
            {points.map(point => <Cell key={point.id ?? point.name} fill={point.fill} />)}
          </Pie>
          <Tooltip content={<ChartTooltip unit={unit} />} />
        </PieChart>
      </ResponsiveContainer>
    </div> : <Empty>{empty ?? 'No data in this scope.'}</Empty>}
    <ChartKey points={points} />
  </Panel>
}
